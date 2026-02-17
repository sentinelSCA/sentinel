while True:
        try:
            cmd = input(">>> ").strip()
        except EOFError:
            print("\nSentinel shutting down.")
            break

        if cmd.lower() == "exit":
            print("Sentinel shutting down.")
            break

        result = evaluate(cmd)
        log_event(cmd, result)

        print(f"Decision: {result['decision']} | Risk: {result['risk']}")
        print(f"Reason: {result['reason']}\n")
