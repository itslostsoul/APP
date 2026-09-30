import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** The outcome of one detonation: verdict, findings, typed behaviour events and indicators of compromise. */
final class Analysis {

    /** One observed behaviour. type: process | file | network | persistence. */
    record Event(String type, String severity, String label, String detail, boolean blocked, int pid) {}

    /** A scored conclusion drawn from the events. */
    record Finding(String id, String severity, String title, String detail, int points) {}

    enum Level {
        CLEAN("clean", "Nothing suspicious observed"),
        SUSPICIOUS("suspicious", "Suspicious"),
        LIKELY_MALICIOUS("likely_malicious", "Likely malicious"),
        MALICIOUS("malicious", "Malicious"),
        INCONCLUSIVE("inconclusive", "Inconclusive");

        final String code;
        final String label;

        Level(String code, String label) {
            this.code = code;
            this.label = label;
        }

        static Level forScore(int score) {
            if (score >= 70) return MALICIOUS;
            if (score >= 40) return LIKELY_MALICIOUS;
            if (score >= 15) return SUSPICIOUS;
            return CLEAN;
        }
    }

    String id;
    Instant createdAt = Instant.now();
    boolean failed;
    String error;                     // set when the analysis itself failed (never treated as malware behaviour)

    SampleIntake.SampleInfo sample;
    String image;
    int exitCode = -1;
    boolean timedOut;
    long durationMs;
    long timeoutSeconds;

    int score;
    Level level = Level.INCONCLUSIVE;

    final List<Finding> findings = new ArrayList<>();
    final List<Event> events = new ArrayList<>();
    final Set<String> iocNetwork = new LinkedHashSet<>();
    final Set<String> iocFiles = new LinkedHashSet<>();
    final Set<String> iocProcesses = new LinkedHashSet<>();
    final List<String> output = new ArrayList<>();
    final List<String> notes = new ArrayList<>();
    final List<String> rawLog = new ArrayList<>();

    long count(String type) {
        return events.stream().filter(e -> e.type().equals(type)).count();
    }
}
