import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Scanner;

/**
 * Command-line front end.
 *
 *   java Main [-v] &lt;sample&gt;                      analyze a file
 *   java Main --replay &lt;trace&gt; [--sample &lt;file&gt;] [--exit N]   analyze a saved strace log (no Docker)
 *   java Main --gui                              open the desktop app
 *
 * Exit codes: 0 clean, 10 suspicious, 20 likely malicious, 30 malicious, 1 analysis failed / bad input.
 */
public final class Main {

    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final boolean COLOR = System.getenv("NO_COLOR") == null
            && (System.getenv("TERM") != null || System.getenv("WT_SESSION") != null);

    private Main() {}

    public static void main(String[] args) throws Exception {
        boolean verbose = false;
        String sample = null;
        String replay = null;
        int replayExit = 0;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-h", "--help" -> { usage(); return; }
                case "-v", "--verbose" -> verbose = true;
                case "--gui" -> { SandboxGUI.main(new String[0]); return; }
                case "--replay" -> replay = need(args, ++i, "--replay");
                case "--sample" -> sample = need(args, ++i, "--sample");
                case "--exit" -> replayExit = Integer.parseInt(need(args, ++i, "--exit"));
                default -> sample = args[i];
            }
        }

        final boolean showTrace = verbose;
        java.util.function.Consumer<LogEvent> printer = e -> {
            if (e.isNoise() && !showTrace) return;
            System.out.println(format(e));
        };

        Analysis result;
        try {
            if (replay != null) {
                Path trace = Paths.get(replay);
                if (!Files.isRegularFile(trace)) fail("Trace file not found: " + trace);
                String subject = sample != null ? sample : replay;
                result = DockerOrchestrator.replay(SampleIntake.inspect(subject), trace, replayExit, printer);
            } else {
                if (sample == null) {
                    System.out.print("Path to the suspicious file: ");
                    try (Scanner sc = new Scanner(System.in)) {
                        sample = sc.nextLine().trim();
                    }
                }
                SampleIntake.SampleInfo info = SampleIntake.inspect(stripQuotes(sample));
                System.out.println(format(LogEvent.of(LogEvent.Kind.SYSTEM,
                        info.name() + "  " + info.typeLabel() + ", " + SampleIntake.humanSize(info.size()))));
                System.out.println(format(LogEvent.of(LogEvent.Kind.SYSTEM, "SHA-256 " + info.sha256())));
                if (!info.supported()) fail(info.unsupportedReason());
                result = DockerOrchestrator.run(info, printer);
            }
        } catch (IOException e) {
            fail(e.getMessage());
            return;
        }

        System.out.println();
        System.out.println(ReportGenerator.toText(result));
        System.exit(exitCodeFor(result));
    }

    static int exitCodeFor(Analysis a) {
        if (a.failed) return 1;
        return switch (a.level) {
            case CLEAN -> 0;
            case SUSPICIOUS -> 10;
            case LIKELY_MALICIOUS -> 20;
            case MALICIOUS -> 30;
            case INCONCLUSIVE -> 1;
        };
    }

    private static String format(LogEvent e) {
        String tag;
        String color;
        switch (e.kind()) {
            case SYSTEM -> { tag = "SYS"; color = "36"; }
            case SUCCESS -> { tag = "OK"; color = "32"; }
            case WARN -> { tag = "WARN"; color = "33"; }
            case ERROR -> { tag = "ERROR"; color = "31"; }
            case OUTPUT -> { tag = "OUT"; color = "0"; }
            case EXEC -> { tag = "EXEC"; color = "33"; }
            case FILE -> { tag = "FILE"; color = "34"; }
            case NET -> { tag = "NET"; color = "35"; }
            default -> { tag = "TRACE"; color = "90"; }
        }
        String time = LocalTime.now().format(CLOCK);
        String label = String.format("%-5s", tag);
        return COLOR
                ? "\u001b[90m" + time + "\u001b[0m  \u001b[" + color + "m" + label + "\u001b[0m  " + e.text()
                : time + "  " + label + "  " + e.text();
    }

    private static String need(String[] args, int i, String flag) {
        if (i >= args.length) fail(flag + " needs a value");
        return args[i];
    }

    private static String stripQuotes(String s) {
        return s.length() > 1 && s.startsWith("\"") && s.endsWith("\"") ? s.substring(1, s.length() - 1) : s;
    }

    private static void fail(String message) {
        System.err.println("Error: " + message);
        System.exit(1);
    }

    private static void usage() {
        System.out.println("""
                AMAS - Automated Malware Analysis Sandbox

                Usage:
                  java -cp out Main [-v] <sample>        analyze a file in a disposable container
                  java -cp out Main --replay <trace.txt> [--sample <file>] [--exit N]
                                                         analyze a saved strace log (no Docker needed)
                  java -cp out Main --gui                open the desktop app

                Options:
                  -v, --verbose   show raw system-call lines too

                Exit codes: 0 clean, 10 suspicious, 20 likely malicious, 30 malicious, 1 failed
                """);
    }
}
