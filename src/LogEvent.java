/** One classified line of live activity, shared by the CLI, the GUI and the analyzer. */
record LogEvent(Kind kind, String text, long timestamp) {

    enum Kind {
        SYSTEM,   // orchestrator status
        SUCCESS,
        WARN,
        ERROR,
        OUTPUT,   // what the sample itself printed
        EXEC,     // process spawned
        FILE,     // interesting file activity
        NET,      // network activity
        TRACE     // raw syscall noise, only shown in verbose mode
    }

    static LogEvent of(Kind kind, String text) {
        return new LogEvent(kind, text, System.currentTimeMillis());
    }

    boolean isNoise() { return kind == Kind.TRACE; }
}
