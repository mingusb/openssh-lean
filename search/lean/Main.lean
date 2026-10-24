import SignalSearch.Worker

unsafe def main (args : List String) : IO UInt32 :=
  SignalSearch.workerMain args
