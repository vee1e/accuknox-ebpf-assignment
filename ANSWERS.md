# Problem 3: Go snippet explained

```go
package main

import "fmt"

func main() {
    cnp := make(chan func(), 10)
    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
            }
        }()
    }
    cnp <- func() {
        fmt.Println("HERE1")
    }
    fmt.Println("Hello")
}
```

## 1. How the constructs work

- `make(chan func(), 10)` creates a buffered channel (a typed queue) that
  carries values of type `func()` (a function taking no arguments and
  returning nothing). Capacity 10 means up to 10 sends queue without a
  receiver waiting. An unbuffered channel would block the sender until a
  worker receives.
- `go func() { ... }()` starts a goroutine (a lightweight thread managed by
  the Go runtime, starting with a ~8KB stack that grows as needed). The
  loop starts 4 of them.
- `for f := range cnp` receives from the channel in a loop. Each iteration
  blocks until a value arrives. The loop ends only when the channel is
  closed and drained. This channel is never closed, so the workers loop
  until the program exits.

## 2. Use cases

This is a worker pool (a fixed set of workers pulling tasks from a shared
queue). It fits background job processing: HTTP handlers enqueueing work,
fan-out task queues, or rate-limited pipelines where you want at most N
tasks running at once. The buffered channel smooths bursts: producers do
not block until the buffer fills.

## 3. Why the loop runs 4 times

The loop spawns the pool: 4 workers pulling from the same channel, so up
to 4 tasks run concurrently. 4 is arbitrary here; in real code it is tuned
to the workload (roughly CPU count for CPU-bound work, higher for
network-bound work).

## 4. What `make(chan func(), 10)` does

It allocates a buffered channel of capacity 10 holding `func()` values.
The single send in `main` therefore never blocks: it lands in the buffer
even if no worker has been scheduled yet.

## 5. Why "HERE1" is not printed

Sending only queues the task. A worker must be scheduled by the runtime to
receive it and call `f()`, but `main` does not wait: it prints "Hello" and
returns, and returning from `main` ends the whole program immediately,
killing the workers. In practice the send sits in the buffer and the
program exits before any worker runs, so only "Hello" appears. (Scheduling
is a race, so "HERE1" could appear on some runs, but it is not waited on.)

Two more defects worth noting: the channel is never closed, so the
`range` loops never end, and there is no `sync.WaitGroup` (a counter that
lets `main` wait for tasks), so task completion is unobserved.

## Fixed version

```go
package main

import (
    "fmt"
    "sync"
)

func main() {
    cnp := make(chan func(), 10)
    var tasks sync.WaitGroup   // tracks enqueued tasks
    var workers sync.WaitGroup // tracks worker goroutines
    for i := 0; i < 4; i++ {
        workers.Add(1)
        go func() {
            defer workers.Done()
            for f := range cnp {
                f()
                tasks.Done()
            }
        }()
    }
    tasks.Add(1)
    cnp <- func() {
        fmt.Println("HERE1")
    }
    fmt.Println("Hello")
    close(cnp) // no more tasks: workers exit after draining the buffer
    tasks.Wait()
    workers.Wait()
}
```

`tasks` makes `main` wait for the queued function, so "HERE1" always
prints. `close(cnp)` lets the `range` loops terminate so the workers stop
instead of leaking, and `workers.Wait()` joins them before exit.
