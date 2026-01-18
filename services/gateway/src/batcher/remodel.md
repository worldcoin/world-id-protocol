 Can we design a total rework of how operation batching works in the world id gateway. First major rearchitecting is that we have a single type     
  that handles all batching, and transaction submission. A `PendingBatchFut` is spawned as a task on a `JoinSet` owned by the `OpsBatcher`. It       
  is the role of the `PendingBatchFut` to resolve, and update all statuses in the `RequestsTracker` of all operations submitted. \                   
  \                                                                                                                                                  
  Furthermore an `Ordering<P: OrderingPolicy>` will be implemented for all Operation types. This policy defines precedence with respect to other     
  operations. The first policy we will implement is a greedy policy in favor of fulfilling `createAccount` operations over any other type.           
  However an additional signal will be implemented with this policy that checks `receivedAt` time. Operations that were received longer ago          
  should get precedence in ordering. \                                                                                                               
  \                                                                                                                                                  
  It is the `OpsBatcher`s responsibility to order dependent operations with respect to each other. For example nonce gaps must be queued for the     
  same signer. And operations acting on adjacent nonces must be ordered in acending order. Very similar to the ethereum transaction pool             
  policy.\                                                                                                                                           
  \                                                                                                                                                  
  The `PendingBatchFut` will be initialized with a threshold gas capacity by the `OpsBatcher` based on how close the current base fee is to the      
  `max-base-fee`. It should also take into account the size of the pending queue, and increase batch size when back pressure is high. The            
  `PendingBatchFut` will also simulate full batches while it is waiting to be resolved, and evict any operations which cause reverts. We will        
  use the `aggregate3` multicall method with allowRevert = true. Then we will parse all call responses, and determine any reverts from `success      
  = false` on the call result. Then we will parse the revert data, and set the status of any invalid ops in the `RequestTracker`.\                   
  \                                                                                                                                                  
  The `OpsBatcher` will hold a task permit limiting the amount of concurrent batches that can be in flight at any time, and will hold run a long     
  running task called `ChainMonitor` which informs the trend over a window of time in  the base fee, and capacity.\                                  
  \                                                                                                                                                  
  The `PendingBatchFut` has the sole responsibility to ensure it's transaction gets mined. If a transaction has not been mined over a given          
  timeout it should try re-estimating gas, and escalating fees if necessary. `PendingBatchFut` will implement `Future`, and will yield a             
  `FinalizedBatch` through a `oneshot::channel<FinalizedBatch>` when all ops have been finalized. This will include a `HashMap<Id, OpStatus>`        
  where enum OpStatus { Finalized { hash: ... }, Failed { reason: error }, Other { reason: Box<dyn std::fmt::Debug> }. The `OpsBatcher` will         
  consume resolved `PendingBatchFut`s, and update the `RequestTracker` status from a single writer thread.\                                          
  \                                                                                                                                                  
  The `OpsBatcher` will also implement all necessary `pre_flight_checks` on every inbound operation it receives prior to allocating it to a          
  `PendingBatchFut`. These are local checks that can be done to validate the correctness of an operation without calling the chain.\                 
  \                                                                                                                                                  
  Finally metrics should be added for all high signal data in the `OpsBatcher` e.g. chain gas info, duration, backlog, signer balance, and a lot     
  more.                                                                                