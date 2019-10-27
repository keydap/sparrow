package repl

import (
	"bytes"
	"encoding/gob"
	bolt "github.com/coreos/bbolt"
	logger "github.com/juju/loggo"
	"sparrow/utils"
)

var (
	// a bucket that holds the pending join requests
	BUC_SENT_JOIN_REQUESTS     = []byte("sent_join_requests")
	BUC_RECEIVED_JOIN_REQUESTS = []byte("received_join_requests")
	BUC_PEERS                  = []byte("peers")
	BUC_SELF_STATE             = []byte("self_state")
	keySelfWebHookToken        = []byte("selfWebhookToken")
	keyClonedFrom              = []byte("clonedFrom")
	keyClonedAt                = []byte("clonedAt")
)
var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.repl.silo")
}

type ReplSilo struct {
	db           *bolt.DB
	WebHookToken string // webhook token of this server
	clonedFrom   uint16
	clonedAt     int64
}

func OpenReplSilo(path string) (*ReplSilo, error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	token := ""
	var clonedFrom uint16
	var clonedAt int64
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_SENT_JOIN_REQUESTS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_RECEIVED_JOIN_REQUESTS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_PEERS)
		if err != nil {
			return err
		}

		buck, err := tx.CreateBucketIfNotExists(BUC_SELF_STATE)
		if err != nil {
			return err
		}

		data := buck.Get(keySelfWebHookToken)
		if data == nil {
			token = utils.NewRandShaStr()
			buck.Put(keySelfWebHookToken, []byte(token))
		} else {
			token = string(data)
		}

		data = buck.Get(keyClonedFrom)
		if data != nil {
			clonedFrom = utils.BtoUint16(data)
		}

		data = buck.Get(keyClonedAt)
		if data != nil {
			clonedAt = utils.Btoi(data)
		}

		return nil
	})

	if err != nil {
		log.Criticalf("Errors while opening the replication silo %s", err.Error())
		return nil, err
	}

	rl := &ReplSilo{}
	rl.db = db
	rl.WebHookToken = token
	rl.clonedFrom = clonedFrom
	rl.clonedAt = clonedAt

	log.Debugf("opened replication silo")
	return rl, nil
}

func (rl *ReplSilo) IsCloned() bool {
	return rl.clonedFrom != 0
}

func (rl *ReplSilo) SetClonedFrom(serverId uint16) error {
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		}
	}()

	buck := tx.Bucket(BUC_SELF_STATE)
	err = buck.Put(keyClonedFrom, utils.Uint16tob(serverId))
	t := utils.DateTimeMillis()
	if err == nil {
		err = buck.Put(keyClonedAt, utils.Itob(t))
	}

	if err == nil {
		rl.clonedFrom = serverId
		rl.clonedAt = t
		tx.Commit()
	}

	return err
}

func (rl *ReplSilo) AddSentJoinReq(req JoinRequest) error {
	return rl._addJoinReq(req, BUC_SENT_JOIN_REQUESTS)
}

func (rl *ReplSilo) AddReceivedJoinReq(req JoinRequest) error {
	return rl._addJoinReq(req, BUC_RECEIVED_JOIN_REQUESTS)
}

func (rl *ReplSilo) _addJoinReq(req JoinRequest, bucketName []byte) error {
	key := utils.Uint16tob(req.ServerId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		}
	}()

	buck := tx.Bucket(bucketName)
	data := buck.Get(key)
	if data != nil {
		log.Debugf("replacing an existing join request for the server with ID %d", req.ServerId)
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(req)
	if err != nil {
		return err
	}
	err = buck.Put(key, buf.Bytes())
	if err == nil {
		tx.Commit()
	}

	return err
}

func (rl *ReplSilo) DeleteSentJoinRequest(serverId uint16) error {
	return rl._deleteJoinRequest(serverId, BUC_SENT_JOIN_REQUESTS)
}

func (rl *ReplSilo) DeleteReceivedJoinRequest(serverId uint16) error {
	return rl._deleteJoinRequest(serverId, BUC_RECEIVED_JOIN_REQUESTS)
}

func (rl *ReplSilo) _deleteJoinRequest(serverId uint16, bucketName []byte) error {
	key := utils.Uint16tob(serverId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		}
	}()

	buck := tx.Bucket(bucketName)
	err = buck.Delete(key)
	if err == nil {
		tx.Commit()
	}
	return err
}

func (rl *ReplSilo) GetSentJoinRequests() []JoinRequest {
	return rl._getJoinRequests(BUC_SENT_JOIN_REQUESTS)
}

func (rl *ReplSilo) GetReceivedJoinRequests() []JoinRequest {
	return rl._getJoinRequests(BUC_RECEIVED_JOIN_REQUESTS)
}

func (rl *ReplSilo) _getJoinRequests(bucketName []byte) []JoinRequest {
	requests := make([]JoinRequest, 0)
	tx, err := rl.db.Begin(false)
	if err != nil {
		log.Warningf("%#v", err)
		return requests
	}

	defer tx.Rollback()

	buck := tx.Bucket(bucketName)
	cursor := buck.Cursor()

	var buf bytes.Buffer
	dec := gob.NewDecoder(&buf)
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		buf.Write(v)
		var r JoinRequest
		err = dec.Decode(&r)
		if err == nil {
			requests = append(requests, r)
		}
		buf.Reset()
	}

	return requests
}

func (rl *ReplSilo) AddReplicationPeer(req *ReplicationPeer) error {
	key := utils.Uint16tob(req.ServerId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	buck := tx.Bucket(BUC_PEERS)
	data := buck.Get(key)
	if data != nil {
		log.Debugf("replacing existing entry of replication peer with ID %d", req.ServerId)
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(req)
	if err != nil {
		return err
	}
	err = buck.Put(key, buf.Bytes())

	return err
}

func (rl *ReplSilo) DeleteReplicationPeer(serverId uint16) error {
	key := utils.Uint16tob(serverId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		}
	}()

	buck := tx.Bucket(BUC_PEERS)
	err = buck.Delete(key)
	if err == nil {
		tx.Commit()
		log.Debugf("deleted replication peer with ID %d", serverId)
	}
	return err
}

func (rl *ReplSilo) GetReplicationPeer(serverId uint16) *ReplicationPeer {
	key := utils.Uint16tob(serverId)
	tx, err := rl.db.Begin(false)
	if err != nil {
		return nil
	}

	defer func() {
		e := recover()
		if e != nil {
			log.Warningf("%#v", e)
		}
		tx.Rollback()
	}()

	buck := tx.Bucket(BUC_PEERS)
	data := buck.Get(key)
	var peer *ReplicationPeer
	if data != nil {
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		dec.Decode(&peer)
	}

	return peer
}

func (rl *ReplSilo) GetReceivedJoinRequest(serverId uint16) *JoinRequest {
	return rl._getJoinRequest(serverId, BUC_RECEIVED_JOIN_REQUESTS)
}

func (rl *ReplSilo) _getJoinRequest(serverId uint16, buckName []byte) *JoinRequest {
	key := utils.Uint16tob(serverId)
	tx, err := rl.db.Begin(false)
	if err != nil {
		return nil
	}

	defer func() {
		e := recover()
		if e != nil {
			log.Warningf("%#v", e)
		}
		tx.Rollback()
	}()

	buck := tx.Bucket(buckName)
	data := buck.Get(key)
	var joinReq JoinRequest
	if data != nil {
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		dec.Decode(&joinReq)
	}

	return &joinReq
}

func (rl *ReplSilo) GetReplicationPeers() map[uint16]*ReplicationPeer {
	peers := make(map[uint16]*ReplicationPeer, 0)
	tx, err := rl.db.Begin(false)
	if err != nil {
		return peers
	}

	defer func() {
		e := recover()
		if e != nil {
			log.Warningf("%#v", e)
		}
		tx.Rollback()
	}()

	buck := tx.Bucket(BUC_PEERS)
	cursor := buck.Cursor()
	var buf bytes.Buffer
	dec := gob.NewDecoder(&buf)
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		var p ReplicationPeer
		buf.Write(v)
		err = dec.Decode(&p)
		buf.Reset()
		if err != nil {
			log.Warningf("%#v", err)
			continue
		}
		peers[p.ServerId] = &p
	}

	return peers
}

func (rl *ReplSilo) Close() {
	rl.db.Close()
}
