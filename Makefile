client:
	ant -f ./ClientA -Dnb.internal.action.name=run run
server:
	ant -f ./ClientB -Dnb.internal.action.name=run run
