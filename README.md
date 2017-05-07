My OMS experimental agent sending network latency and network bandtwith to OMS workspace.

Please create directory pingdata/ and speeddata/ for agents in same directory as scripts, than you can run scripts from crontab. Data directories are storage for monitoring events which cannot be send to OMS server because of connectivity problem - but events are collected by agent, agents sends all storred events in next sending round when connection is restored.
