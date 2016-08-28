package main

type Node struct {
	Domain string
	Depth  int
}

type Queue []*Node

func (q *Queue) Push(n *Node) {
	*q = append(*q, n)
}

func (q *Queue) Pop() (n *Node) {
	n = (*q)[0]
	*q = (*q)[1:]
	return
}

func (q *Queue) Len() int {
	return len(*q)
}
