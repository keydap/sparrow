package silo

import (
	"bytes"
	"fmt"
	"github.com/boltdb/bolt"
	"math"
	"sparrow/scim/base"
	"sparrow/scim/schema"
	"strings"
)

func getOptimizedResults(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {
	setAtType(node, rt)
	scanCounts(node, rt, tx, sl)
	return gatherCandidates(node, rt, tx, sl, candidates)
}

// set the AttributeType on all leaf nodes
func setAtType(node *base.FilterNode, rt *schema.ResourceType) {
	switch node.Op {
	default:
		atType := rt.GetAtType(node.Name)
		node.SetAtType(atType)

	case "NOT", "AND", "OR":
		for _, child := range node.Children {
			setAtType(child, rt)
		}
	}
}

// --------------- gather the candidate set -----

func gatherCandidates(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {

	if node.Count == 0 {
		return 0
	}

	switch node.Op {
	case "EQ":
		return eqCandidates(node, rt, tx, sl, candidates)

	case "NE":
		// NE is worstcase, the entire DB must be scanned
		return math.MaxInt64

	case "CO", "SW", "EW":
		return containsStringCandidates(node, rt, tx, sl, candidates)

	case "GT", "LT", "GE", "LE":
		return compareCandidates(node, rt, tx, sl, candidates)

	case "PR":
		return prCandidates(node, rt, tx, sl, candidates)

	case "NOT":
		gatherCandidates(node.Children[0], rt, tx, sl, candidates)
		// NOT is worstcase, the entire DB must be scanned
		return math.MaxInt64

	case "OR":
		return orCandidates(node, rt, tx, sl, candidates)

	case "AND":
		return andCandidates(node, rt, tx, sl, candidates)

	default:
		panic(fmt.Errorf("Unknown operator %s", node.Op))
	}

	return 0
}

func orCandidates(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {
	var totalResults int64

	for _, child := range node.Children {
		if child.Count == 0 {
			continue
		} else if child.Count == math.MaxInt64 {
			return child.Count
		}

		tmp := gatherCandidates(node, rt, tx, sl, candidates)
		if tmp == math.MaxInt64 {
			return tmp
		} else {
			totalResults += tmp
		}
	}

	return totalResults
}

func andCandidates(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {
	var minCount int64
	minCount = math.MaxInt64

	minChildIndex := 0 // the index of the child with least count

	for i, child := range node.Children {
		if child.Count == 0 {
			return 0
		}

		if child.Count < minCount {
			minCount = child.Count
			minChildIndex = i
		}
	}

	minChild := node.Children[minChildIndex]
	// gather candidates for the node with least count
	return gatherCandidates(minChild, rt, tx, sl, candidates)
}

func eqCandidates(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {
	if node.GetAtType() == nil { // there is no such AT type
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]

	var count int64

	if idx != nil {
		if idx.AllowDupKey {
			rids := idx.GetRids(node.NvBytes, tx)
			for _, v := range rids {
				if _, ok := candidates[v]; !ok {
					candidates[v] = nil
					count++
				}
			}
		} else {
			rid := idx.GetRid(node.NvBytes, tx)
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

func prCandidates(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {
	if node.GetAtType() == nil { // there is no such AT type for this resource
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]

	var count int64

	if idx != nil {
		prIdx := sl.sysIndices[rt.Name]["presence"]

		// presence index always supports duplicate keys
		rids := prIdx.GetRids([]byte(node.Name), tx)
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

func containsStringCandidates(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {
	if node.GetAtType() == nil { // there is no such AT type
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]
	if idx != nil {
		var count int64
		cursor := idx.cursor(tx)

		nval := node.NvBytes

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if idx.AllowDupKey {
				if strings.HasSuffix(string(k), "_count") {
					continue
				}
			}
			switch node.Op {
			case "CO":
				if bytes.Contains(k, nval) {
					if idx.AllowDupKey {
						rids := idx.GetRids(k, tx)
						for _, id := range rids {
							candidates[id] = nil
						}
						count += int64(len(rids))
					} else {
						candidates[string(v)] = nil
						count++
					}
				}

			case "SW":
				if bytes.HasPrefix(k, nval) {
					if idx.AllowDupKey {
						rids := idx.GetRids(k, tx)
						for _, id := range rids {
							candidates[id] = nil
						}
						count += int64(len(rids))
					} else {
						candidates[string(v)] = nil
						count++
					}
				}

			case "EW":
				if bytes.HasSuffix(k, nval) {
					if idx.AllowDupKey {
						rids := idx.GetRids(k, tx)
						for _, id := range rids {
							candidates[id] = nil
						}
						count += int64(len(rids))
					} else {
						candidates[string(v)] = nil
						count++
					}
				}
			}
		}

		log.Debugf("Found index on attribute %s of resource type %s, count for key %s != %d", node.Name, rt.Name, node.Value, count)
		return count
	} else {
		log.Debugf("No index found on attribute %s of resource type %s (for %s scan), using complete DB scan", node.Name, rt.Name, node.Op)
	}

	return math.MaxInt64
}

func compareCandidates(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo, candidates map[string]*base.Resource) int64 {
	atType := node.GetAtType()
	if atType == nil { // there is no such AT type
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]
	if idx != nil {
		var count int64

		cursor := idx.cursor(tx)
		k, v := cursor.Seek(node.NvBytes)

		switch node.Op {
		case "GE", "LE":
			if bytes.Compare(node.NvBytes, k) == 0 {
				count++
				candidates[string(v)] = nil
			}
		}

		switch node.Op {
		case "GT", "GE":
			for k, v := cursor.Next(); k != nil; k, v = cursor.Next() {

				if idx.AllowDupKey {
					if strings.HasSuffix(string(k), "_count") {
						continue
					}
				}

				if idx.AllowDupKey {
					rids := idx.GetRids(k, tx)
					for _, id := range rids {
						candidates[id] = nil
					}
					count += int64(len(rids))
				} else {
					candidates[string(v)] = nil
					count++
				}
			}
		case "LT", "LE":
			for k, v := cursor.Prev(); k != nil; k, v = cursor.Prev() {
				if idx.AllowDupKey {
					if strings.HasSuffix(string(k), "_count") {
						continue
					}
				}

				if idx.AllowDupKey {
					rids := idx.GetRids(k, tx)
					for _, id := range rids {
						candidates[id] = nil
					}
					count += int64(len(rids))
				} else {
					candidates[string(v)] = nil
					count++
				}
			}
		}

		log.Debugf("Found index on attribute %s of resource type %s, count for key %s != %d", node.Name, rt.Name, node.Value, count)
		return count
	} else {
		log.Debugf("No index found on attribute %s of resource type %s (for %s scan), using complete DB scan", node.Name, rt.Name, node.Op)
	}

	return math.MaxInt64
}

// ------------ end of gathering candidates -----

// ----------------------- scan the nodes and apply count heuristics -----
func scanCounts(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) {
	var count int64
	count = math.MaxInt64 // the default worst case count

	switch node.Op {
	case "EQ":
		count = equalityScan(node, rt, tx, sl)

	case "NE":
		count = math.MaxInt64

	case "CO", "SW", "EW":
		count = containsStringScan(node, rt, tx, sl)

	case "GT", "LT", "GE", "LE":
		count = compareScan(node, rt, tx, sl)

	case "PR":
		count = presenceScan(node, rt, tx, sl)

	case "NOT":
		scanCounts(node.Children[0], rt, tx, sl)
		// NOT is always a worstcase scenario
		count = math.MaxInt64

	case "OR":
		count = orScan(node, rt, tx, sl)

	case "AND":
		count = andScan(node, rt, tx, sl)
	}

	if count < 0 {
		count = math.MaxInt64
	}

	node.Count = count
}

func equalityScan(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
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

func containsStringScan(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	node.ResType = rt
	atType := rt.GetAtType(node.Name)
	node.SetAtType(atType)
	if atType == nil {
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]
	if idx != nil {
		cursor := idx.cursor(tx)

		var count, countLimit int64

		nval := node.NvBytes

		countLimit = 100

		countKeySuffix := []byte("_count")

		for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
			if idx.AllowDupKey {
				if bytes.HasSuffix(k, countKeySuffix) {
					continue
				}
			}

			switch node.Op {
			case "CO":
				if bytes.Contains(k, nval) {
					if idx.AllowDupKey {
						count += idx.keyCount(string(k), tx)
					} else {
						count++
					}
				}

			case "SW":
				if bytes.HasPrefix(k, nval) {
					if idx.AllowDupKey {
						count += idx.keyCount(string(k), tx)
					} else {
						count++
					}
				}

			case "EW":
				if bytes.HasSuffix(k, nval) {
					if idx.AllowDupKey {
						count += idx.keyCount(string(k), tx)
					} else {
						count++
					}
				}
			}

			// gather a limited number of them
			// cause this cursor will be scanned completely during candidate gathering
			if count == countLimit {
				break
			}
		}

		log.Debugf("Found index on attribute %s of resource type %s, count for key %s != %d", node.Name, rt.Name, node.Value, count)
		return count
	} else {
		log.Debugf("No index found on attribute %s of resource type %s (for %s scan), using complete DB scan", node.Name, rt.Name, node.Op)
	}

	return math.MaxInt64
}

func compareScan(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	node.ResType = rt
	atType := rt.GetAtType(node.Name)
	node.SetAtType(atType)
	if atType == nil {
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]
	if idx != nil {
		var count, countLimit int64

		countLimit = 100

		cursor := idx.cursor(tx)
		k, _ := cursor.Seek(node.NvBytes)

		switch node.Op {
		case "GE", "LE":
			if bytes.Compare(node.NvBytes, k) == 0 {
				count++
			}
		}

		switch node.Op {
		case "GT", "GE":
			for k, _ := cursor.Next(); k != nil; k, _ = cursor.Next() {

				if idx.AllowDupKey {
					kStr := string(k)
					if strings.HasSuffix(kStr, "_count") {
						pos := strings.LastIndex(kStr, "_count")
						count += idx.keyCount(kStr[0:pos], tx)
					}
				} else {
					count++
				}

				// gather a limited number of them
				// cause this cursor will be scanned completely during candidate gathering
				if count == countLimit {
					break
				}
			}
		case "LT", "LE":
			for k, _ := cursor.Prev(); k != nil; k, _ = cursor.Prev() {
				if idx.AllowDupKey {
					kStr := string(k)
					if strings.HasSuffix(kStr, "_count") {
						pos := strings.LastIndex(kStr, "_count")
						count += idx.keyCount(kStr[0:pos], tx)
					}
				} else {
					count++
				}

				// gather a limited number of them
				// cause this cursor will be scanned completely during candidate gathering
				if count == countLimit {
					break
				}
			}
		}

		log.Debugf("Found index on attribute %s of resource type %s, count for key %s != %d", node.Name, rt.Name, node.Value, count)
		return count
	} else {
		log.Debugf("No index found on attribute %s of resource type %s (for %s scan), using complete DB scan", node.Name, rt.Name, node.Op)
	}

	return math.MaxInt64
}

func presenceScan(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	// should we consider the count for more than one resource if searched at the server root? YES
	node.ResType = rt
	atType := rt.GetAtType(node.Name)
	node.SetAtType(atType)
	if atType == nil {
		return 0
	}

	idx := sl.indices[rt.Name][node.Name]
	if idx != nil {
		// use the name of the attribute as the value
		count := sl.sysIndices[rt.Name]["presence"].keyCount(node.Name, tx)
		log.Debugf("The attribute %s of resource type %s is indexed, presence count for key %s = %d", node.Name, rt.Name, node.Value, count)
		return count
	} else {
		log.Debugf("The attribute %s of resource type %s is NOT indexed, using complete DB scan for presence evaluation", node.Name, rt.Name)
	}

	return math.MaxInt64
}

func andScan(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	var count int64
	count = math.MaxInt64

	for _, child := range node.Children {
		scanCounts(child, rt, tx, sl)
		if child.Count < count {
			count = child.Count
		}

		if count == 0 {
			break
		}
	}

	return count
}

func orScan(node *base.FilterNode, rt *schema.ResourceType, tx *bolt.Tx, sl *Silo) int64 {
	var count int64
	count = 0

	for _, child := range node.Children {
		scanCounts(child, rt, tx, sl)
		count += child.Count

		if count == math.MaxInt64 {
			break
		}
	}

	return count
}
