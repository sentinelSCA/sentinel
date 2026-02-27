1️⃣ Restart Sentinel API

type: restart_service
target: sentinel-api 
decision: allow
risk: low

Reason:
The enforcement layer itself must remain restartable.


2️⃣ Restart Any Other Service

type: restart_service
target: *
decision: review 
risk: high

Reason:
The enforcement layer itself must remain restartable.


3️⃣ Shell Execution

type: shell
decision: deny
risk: critical

4️⃣ Arbitrary Commands

Any command not explicitly allowed defaults to deny.



Security Guarantees
	•	HMAC signed requests
	•	Strict timestamp window validation
	•	Nonce replay protection
	•	Immutable audit chain
	•	Reputation-based decision adjustment
	•	Strict mode enabled
