package block

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"sort"

	"simple_eth/types"

	"crypto/sha256"
	"github.com/ethereum/go-ethereum/common"
)

// ProofStep describes a single SPV proof element.
type ProofStep struct {
	Hash          []byte
	SiblingOnLeft bool
}

// MerkleTree represents a classic binary Merkle tree.
type MerkleTree struct {
	Root   *MerkleNode
	leaves []*MerkleNode
}

// MerkleNode is a node in the Merkle tree.
type MerkleNode struct {
	Left   *MerkleNode
	Right  *MerkleNode
	Parent *MerkleNode
	Data   []byte
	isLeft bool
}

// NewMerkleTree builds a Merkle tree from arbitrary byte slices.
func NewMerkleTree(data [][]byte) *MerkleTree {
	// TODO: Lab 2, build Merkle tree bottom-up by hashing pairs.
	if len(data) == 0 {
		return &MerkleTree{}
	}

	var leaves []*MerkleNode
	for i := 0; i < len(data); i++ {
		var newMerkleNode MerkleNode
		hash := sha256.Sum256(data[i])
		newMerkleNode.Data = hash[:]
		newMerkleNode.isLeft = true
		leaves = append(leaves, &newMerkleNode)
	}
	nodes := make([]*MerkleNode, len(leaves))
	copy(nodes, leaves)
	for len(nodes) > 1 {
		if len(nodes)%2 == 1 {
			copiedNode := duplicateNode(nodes[len(nodes)-1])
			nodes = append(nodes, copiedNode)
		}
		var nextLevel []*MerkleNode

		for i := 0; i < len(nodes); i += 2 {
			leftNode := nodes[i]
			rightNode := nodes[i+1]
			leftNode.isLeft = true
			rightNode.isLeft = false

			cat := append(leftNode.Data, rightNode.Data...)
			parentHash := sha256.Sum256(cat)
			parentNode := MerkleNode{
				Left:   leftNode,
				Right:  rightNode,
				Parent: nil,
				Data:   parentHash[:],
				isLeft: (i/2)%2 == 0,
			}
			leftNode.Parent = &parentNode
			rightNode.Parent = &parentNode
			nextLevel = append(nextLevel, &parentNode)
		}

		nodes = nextLevel
	}

	root := nodes[0]

	return &MerkleTree{
		Root:   root,
		leaves: leaves,
	}
}

// SPVProof returns the Merkle path for the leaf at index.
func (t *MerkleTree) SPVProof(index int) ([]ProofStep, error) {
	// TODO: Lab 2, provide bottom-up sibling hashes for SPV proof.
	if t == nil || t.Root == nil || len(t.leaves) == 0 {
		return nil, errors.New("merkle tree is empty")
	}

	if index < 0 || index >= len(t.leaves) {
		return nil, errors.New("index out of boundry")
	}

	curNode := t.leaves[index]
	var proofStep []ProofStep

	for curNode.Parent != nil {
		if curNode.isLeft {
			proofStep = append(proofStep, ProofStep{
				Hash:          curNode.Parent.Right.Data,
				SiblingOnLeft: false,
			})
		} else {
			proofStep = append(proofStep, ProofStep{
				Hash:          curNode.Parent.Left.Data,
				SiblingOnLeft: true,
			})
		}
		curNode = curNode.Parent
	}

	return proofStep, nil
}

// VerifyProof verifies an SPV proof against the expected root.
func VerifyProof(leaf []byte, path []ProofStep, expectedRoot []byte) bool {
	// TODO: Lab 2, verify SPV computed root against expected root.
	hash := sha256.Sum256(leaf)
	curLevel := hash[:]
	for _, proofStep := range path {
		var cat []byte
		if proofStep.SiblingOnLeft {
			cat = append(proofStep.Hash, curLevel...)
		} else {
			cat = append(curLevel, proofStep.Hash...)
		}
		catHash := sha256.Sum256(cat)
		curLevel = catHash[:]
	}
	return bytes.Equal(curLevel, expectedRoot)
}

// CalculateMerkleRoot hashes all transactions and returns the root hex string.
func CalculateMerkleRoot(transactions []*types.Transaction) string {
	data := transactionsToData(transactions)
	if len(data) == 0 {
		return ""
	}
	tree := NewMerkleTree(data)
	if tree.Root == nil {
		return ""
	}
	return hex.EncodeToString(tree.Root.Data)
}

// NewMerkleTreeFromTransactions builds a tree directly from transactions.
func NewMerkleTreeFromTransactions(transactions []*types.Transaction) *MerkleTree {
	data := transactionsToData(transactions)
	return NewMerkleTree(data)
}

func duplicateNode(node *MerkleNode) *MerkleNode {
	if node == nil {
		return nil
	}
	dataCopy := make([]byte, len(node.Data))
	copy(dataCopy, node.Data)
	return &MerkleNode{Data: dataCopy}
}

func transactionsToData(transactions []*types.Transaction) [][]byte {
	if len(transactions) == 0 {
		return nil
	}
	data := make([][]byte, 0, len(transactions))
	for _, tx := range transactions {
		if tx == nil {
			continue
		}
		bytes, err := hex.DecodeString(tx.Hash)
		if err != nil {
			bytes = []byte(tx.Hash)
		}
		data = append(data, bytes)
	}
	return data
}

// CalculateAccountMerkleRoot hashes all accounts (sorted by address) and returns the root hex string.
func CalculateAccountMerkleRoot(state types.State) string {
	if len(state) == 0 {
		return ""
	}
	data := accountsToData(state)
	if len(data) == 0 {
		return ""
	}
	tree := NewMerkleTree(data)
	if tree.Root == nil {
		return ""
	}
	return hex.EncodeToString(tree.Root.Data)
}

func accountsToData(state types.State) [][]byte {
	addresses := make([]common.Address, 0, len(state))
	for addr, acct := range state {
		if acct == nil {
			continue
		}
		addresses = append(addresses, addr)
	}
	if len(addresses) == 0 {
		return nil
	}
	sort.Slice(addresses, func(i, j int) bool {
		return bytes.Compare(addresses[i].Bytes(), addresses[j].Bytes()) < 0
	})

	data := make([][]byte, 0, len(addresses))
	for _, addr := range addresses {
		acct := state[addr]
		if acct == nil {
			continue
		}
		entry := make([]byte, 0, len(addr.Bytes())+16)
		entry = append(entry, addr.Bytes()...)

		balanceBits := math.Float64bits(acct.Balance)
		tmp := make([]byte, 8)
		binary.BigEndian.PutUint64(tmp, balanceBits)
		entry = append(entry, tmp...)

		binary.BigEndian.PutUint64(tmp, uint64(acct.Nonce))
		entry = append(entry, tmp...)

		data = append(data, entry)
	}
	return data
}
