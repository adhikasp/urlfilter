package urlfilter

import (
	"cmp"
	"slices"
	"sort"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	// ruleIndex is a frozen, hash-sorted index over all host-rule hostnames.
	// It replaces a map[string][]StorageID: entries are (hash, id) pairs sorted
	// by hash, so a lookup is a binary search plus a verification pass over the
	// (rare) hash collisions.  This removes the per-hostname map entry, the
	// per-hostname slice allocation, and the retained hostname strings.
	ruleIndex []hashEntry

	// networkEngine is the network engine constructed from the network rules.
	networkEngine *NetworkEngine

	// rulesStorage is the storage of all rules.
	rulesStorage *filterlist.RuleStorage

	// reqPool is the pool of [rules.Request] values.
	reqPool *syncutil.Pool[rules.Request]

	// rulesPool contains slices of rules for reuse.
	rulesPool *syncutil.Pool[[]*rules.HostRule]

	// rulesCount is the number of rules loaded to the engine.
	rulesCount uint64
}

// hashEntry pairs a hostname hash with the storage ID of a rule that matches
// it.  Hash collisions are resolved by verifying the retrieved rule's
// hostnames, so a collision only costs an extra comparison, never a wrong
// answer.
type hashEntry struct {
	h  uint64
	id filterlist.StorageID
}

// hostHash returns the FNV-1a 64-bit hash of a hostname.
func hostHash(s string) (h uint64) {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)

	h = offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}

	return h
}

// bytesPerRuleEst is the estimate of how many bytes a single rule generally
// takes.  It is based on the AdGuard Base DNS list.
const bytesPerRuleEst = 64

// NewDNSEngine parses the specified filter lists and returns a *DNSEngine built
// from them.  s must not be nil.
func NewDNSEngine(s *filterlist.RuleStorage) (e *DNSEngine) {
	numRulesEst := s.SizeEstimate() / bytesPerRuleEst

	e = &DNSEngine{
		rulesStorage: s,
		ruleIndex:    make([]hashEntry, 0, numRulesEst),
		rulesCount:   0,
		reqPool:      syncutil.NewPool(func() (v *rules.Request) { return &rules.Request{} }),
		rulesPool:    syncutil.NewSlicePool[*rules.HostRule](1),
	}

	netEng := NewNetworkEngineSkipStorageScan(s)
	set := container.NewMapSet[string]()

	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, id := scanner.Rule()
		switch f := f.(type) {
		case *rules.HostRule:
			e.addRule(f, id)
		case *rules.NetworkRule:
			if f.IsHostLevelNetworkRule() {
				netEng.addRule(f, id, set)
			}
		}
	}

	e.rulesCount += netEng.rulesCount
	e.networkEngine = netEng

	// Freeze the index.  A stable sort keeps the rules of one hostname in
	// their insertion order, which the callers rely on for rule precedence.
	slices.SortStableFunc(e.ruleIndex, func(a, b hashEntry) (res int) {
		return cmp.Compare(a.h, b.h)
	})

	return e
}

// Match finds a matching rule for the specified hostname.  It returns true and
// the list of rules found or false and nil.  A list of rules is returned when
// there are multiple host rules matching the same domain, for example:
//
//	192.168.0.1 example.local
//	2000::1 example.local
func (e *DNSEngine) Match(hostname string) (res *DNSResult, matched bool) {
	return e.MatchRequest(&DNSRequest{Hostname: hostname})
}

// getRequestFromPool returns an instance of request from the engine's pool.
// Fills it's properties to match the given DNS request.
func (e *DNSEngine) getRequestFromPool(dReq *DNSRequest) (req *rules.Request) {
	req = e.reqPool.Get()

	req.SourceDomain = ""
	req.SourceHostname = ""
	req.SourceURL = ""

	req.ClientTags = dReq.ClientTags
	req.ClientIP = dReq.ClientIP
	req.ResponseCountry = dReq.ResponseCountry
	req.ResponseASN = dReq.ResponseASN
	req.ClientIdentifiers = dReq.ClientIdentifiers
	req.DNSType = dReq.DNSType
	req.IsAnswer = dReq.Answer

	rules.FillRequestForHostname(req, dReq.Hostname)

	return req
}

// MatchRequestInto matches the specified DNS request and puts the result into
// res.  ok is true if the result has a basic network rule or some host rules.
// req and res must not be nil.  res should be empty or reset using
// [DNSResult.Reset].
//
// NOTE:  For compatibility reasons, it is also false when there are DNS rewrite
// and other kinds of special network rules, so users who need those will need
// to ignore the matched return parameter and instead inspect the results of the
// corresponding DNSResult getters.
//
// TODO(a.garipov):  Refactor the result and remove the exception above.
func (e *DNSEngine) MatchRequestInto(req *DNSRequest, res *DNSResult) (matched bool) {
	if req.Hostname == "" {
		return false
	}

	r := e.getRequestFromPool(req)
	defer e.reqPool.Put(r)

	res.NetworkRules = e.networkEngine.AppendAllMatching(res.NetworkRules, r)
	resultRule := rules.GetDNSBasicRule(res.NetworkRules)
	if resultRule != nil {
		res.NetworkRule = resultRule

		return true
	}

	hostRulesPtr := e.rulesPool.Get()
	defer e.rulesPool.Put(hostRulesPtr)

	*hostRulesPtr = e.appendFromIndex((*hostRulesPtr)[:0], req.Hostname)
	if len(*hostRulesPtr) == 0 {
		return false
	}

	for _, rule := range *hostRulesPtr {
		if rule.IP.Is4() {
			res.HostRulesV4 = append(res.HostRulesV4, rule)
		} else {
			res.HostRulesV6 = append(res.HostRulesV6, rule)
		}
	}

	return true
}

// MatchRequest is like [MatchRequestInto] but returns a new result.  req must
// not be nil.
func (e *DNSEngine) MatchRequest(dReq *DNSRequest) (res *DNSResult, matched bool) {
	res = &DNSResult{}
	matched = e.MatchRequestInto(dReq, res)

	return res, matched
}

// appendFromIndex appends matching rules to matching.
func (e *DNSEngine) appendFromIndex(
	matching []*rules.HostRule,
	hostname string,
) (res []*rules.HostRule) {
	res = matching

	idx := e.ruleIndex
	h := hostHash(hostname)

	i := sort.Search(len(idx), func(i int) (ge bool) { return idx[i].h >= h })
	for ; i < len(idx) && idx[i].h == h; i++ {
		r := e.rulesStorage.RetrieveHostRule(idx[i].id)
		if r != nil && slices.Contains(r.Hostnames, hostname) {
			res = append(res, r)
		}
	}

	return res
}

// addRule adds rule to the index
func (e *DNSEngine) addRule(hostRule *rules.HostRule, id filterlist.StorageID) {
	for _, hostname := range hostRule.Hostnames {
		e.ruleIndex = append(e.ruleIndex, hashEntry{h: hostHash(hostname), id: id})
	}

	e.rulesCount++
}

// RulesCount returns the number of rules added to the engine.
func (e *DNSEngine) RulesCount() (n uint64) {
	return e.rulesCount
}
