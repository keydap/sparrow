package silo

import (
	"fmt"
	"github.com/boltdb/bolt"
	"math"
	"sparrow/scim/provider"
	"sparrow/scim/schema"
)

func getOptimizedResults(node *provider.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*provider.Resource) int64 {
	scanCounts(node, rt, tx, sl)
	return gatherCandidates(node, rt, tx, sl, candidates)
}

// --------------- gather the candidate set -----

func gatherCandidates(node *provider.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*provider.Resource) int64 {

	if node.Count == 0 || node.Count == math.MaxInt64 {
		return 0
	}

	switch node.Op {
	case "EQ":
		return eqCandidates(node, rt, tx, sl, candidates)

	case "NE":
	case "CO":
	case "SW":
	case "EW":
	case "GT":
	case "LT":
	case "GE":
	case "LE":
	case "PR":
		return prCandidates(node, rt, tx, sl, candidates)

	case "NOT":
		gatherCandidates(node.Children[0], rt, tx, sl, candidates)
		// NOT is worstcase, the entire DB must be scanned
		return math.MaxInt64

	case "OR":
	case "AND":

	default:
		panic(fmt.Errorf("Unknown operator %s", node.Op))
	}

	return 0
}

func eqCandidates(node *provider.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*provider.Resource) int64 {
	if node.GetAtType() == nil { // there is no such AT type
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]

	var count int64

	if idx != nil {
		if idx.AllowDupKey {
			rids := idx.GetRids(node.Value, tx)
			for _, v := range rids {
				if _, ok := candidates[v]; !ok {
					candidates[v] = nil
					count++
				}
			}
		} else {
			rid := idx.GetRid(node.Value, tx)
			if len(rid) != 0 {
				candidates[rid] = nil
				count++
			}
		}

		return count
	}

	// full db scan
	return math.MaxInt64
}

func prCandidates(node *provider.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*provider.Resource) int64 {
	if node.GetAtType() == nil { // there is no such AT type for this resource
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]

	var count int64

	if idx != nil {
		prIdx := sl.sysIndices[rt.Name]["presence"]

		// presence index always supports duplicate keys
		rids := prIdx.GetRids(node.Name, tx)
		for _, v := range rids {
			if _, ok := candidates[v]; !ok {
				candidates[v] = nil
				count++
			}
		}

		return count
	}

	// full db scan
	return math.MaxInt64
}

// ------------ end of gathering candidates -----

// ----------------------- scan the nodes and apply count heuristics -----
func scanCounts(node *provider.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	var count int64
	count = math.MaxInt64 // the default worst case count

	switch node.Op {
	case "EQ":
		count = equalityScan(node, rt, tx, sl)

	case "NE":
	case "CO":
	case "SW":
	case "EW":
	case "GT":
	case "LT":
	case "GE":
	case "LE":
	case "PR":
		count = presenceScan(node, rt, tx, sl)

	case "NOT":
	case "OR":
	case "AND":
	}

	if count < 0 {
		count = math.MaxInt64
	}

	node.Count = count

	return count
}

func equalityScan(node *provider.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	node.ResType = rt
	atType := rt.GetAtType(node.Name)
	node.SetAtType(atType)
	if atType == nil {
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]
	if idx != nil {
		count := idx.keyCount(node.Value, tx)
		log.Debugf("Found index on attribute %s of resource type %s, count for key %s = %d", node.Name, rt.Name, node.Value, count)
		return count
	} else {
		log.Debugf("No index found on attribute %s of resource type %s, using complete DB scan", node.Name, rt.Name)
	}

	return math.MaxInt64
}

func presenceScan(node *provider.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	// should we consider the count for more than one resource if searched at the server root? YES
	node.ResType = rt
	atType := rt.GetAtType(node.Name)
	node.SetAtType(atType)
	if atType == nil {
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]
	if idx != nil {
		count := sl.sysIndices[rt.Name]["presence"].keyCount(node.Value, tx)
		log.Debugf("The attribute %s of resource type %s is indexed, presence count for key %s = %d", node.Name, rt.Name, node.Value, count)
		return count
	} else {
		log.Debugf("The attribute %s of resource type %s is NOT indexed, using complete DB scan for key %s for presence evaluation", node.Name, rt.Name, node.Value)
	}

	return math.MaxInt64
}
