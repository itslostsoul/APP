import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.KeyStroke;
import javax.swing.ScrollPaneConstants;
import javax.swing.Scrollable;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.TransferHandler;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.BasicStroke;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.BorderLayout;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Desktop front end for AMAS. */
public final class SandboxGUI {

    private static final int DASHBOARD_PORT = 5000;
    private static final int MAX_EVENTS = 8000;
    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss");

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { Main.main(args); return; }   // any argument means command-line mode
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception ignored) {}
        SwingUtilities.invokeLater(() -> new SandboxGUI().frame.setVisible(true));
    }

    // ------------------------------------------------------------------ state

    private SampleIntake.SampleInfo sample;
    private Analysis last;
    private boolean running;
    private Process dashboardProcess;
    private long runStarted;
    private final List<LogEvent> events = new ArrayList<>();

    // ------------------------------------------------------------------ widgets

    final JFrame frame = new JFrame("AMAS");
    private final StatusPill dockerPill = new StatusPill();
    private final Theme.Btn analyzeBtn = new Theme.Btn("Analyze sample", Theme.Btn.Style.PRIMARY);
    private final Theme.Progress progress = new Theme.Progress();
    private final CardLayout sampleCards = new CardLayout();
    private final JPanel sampleBody = new JPanel(sampleCards);
    private final DropZone dropZone = new DropZone();
    private final JLabel nameLabel = label("", Theme.ui(Font.BOLD, 16f), Theme.TEXT);
    private final JLabel metaLabel = label("", Theme.ui(Font.PLAIN, 12f), Theme.MUTED);
    private final JLabel hashLabel = label("", Theme.mono(Font.PLAIN, 12f), Theme.TEXT);
    private final JLabel warnLabel = label("", Theme.ui(Font.PLAIN, 12f), Theme.DANGER);
    private final Theme.Btn copyHashBtn = new Theme.Btn("Copy", Theme.Btn.Style.LINK);
    private final Theme.StackLight tower = new Theme.StackLight();
    private final Theme.Tag verdictTag = new Theme.Tag();
    private final Theme.Gauge gauge = new Theme.Gauge();
    private final Theme.ScoreText scoreText = new Theme.ScoreText(gauge);
    private final JTextArea verdictSub = new JTextArea("Choose a sample to begin.");
    private final JPanel chips = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
    private final Theme.Btn activityTab = new Theme.Btn("Activity", Theme.Btn.Style.TAB);
    private final Theme.Btn findingsTab = new Theme.Btn("Findings", Theme.Btn.Style.TAB);
    private final CardLayout contentCards = new CardLayout();
    private final JPanel content = new JPanel(contentCards);
    private final JTextPane console = new JTextPane();
    private final ScrollPanel findingsList = new ScrollPanel();
    private final Theme.Toggle verboseToggle = new Theme.Toggle(this::refilter);
    private final JLabel statusLabel = label("Ready", Theme.ui(Font.PLAIN, 12f), Theme.MUTED);

    SandboxGUI() {
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setIconImage(Theme.logoImage(64));
        frame.setSize(1180, 780);
        frame.setMinimumSize(new Dimension(1000, 660));
        frame.setLocationRelativeTo(null);

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(Theme.BG);
        root.add(buildHeader(), BorderLayout.NORTH);
        root.add(buildBody(), BorderLayout.CENTER);
        root.add(buildStatusBar(), BorderLayout.SOUTH);
        frame.setContentPane(root);

        installDragAndDrop(root);
        installShortcuts(root);
        showTab(true);
        resetVerdict();
        onEvent(LogEvent.of(LogEvent.Kind.SYSTEM, "Waiting for a sample. Drop a file anywhere in this window, or choose one."));

        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { shutdown(); }
        });
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "amas-shutdown"));
        refreshDocker();
        new Timer(15000, e -> { if (!running) refreshDocker(); }).start();
    }

    // ------------------------------------------------------------------ layout

    private JComponent buildHeader() {
        JPanel header = new JPanel(new BorderLayout()) {
            @Override protected void paintComponent(Graphics g) {
                g.setColor(Theme.LINE);
                g.fillRect(0, getHeight() - 1, getWidth(), 1);
            }
        };
        header.setOpaque(false);
        header.setBorder(new EmptyBorder(14, 24, 14, 24));

        JPanel brand = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        brand.setOpaque(false);
        brand.add(new JLabel(new ImageIcon(Theme.logoImage(42))));
        JPanel names = stack();
        addRow(names, label("AMAS", Theme.display(22f), Theme.TEXT), 0);
        addRow(names, label("Malware analysis sandbox", Theme.ui(Font.PLAIN, 12f), Theme.MUTED), 0);
        brand.add(names);
        header.add(brand, BorderLayout.WEST);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 3));
        actions.setOpaque(false);
        Theme.Btn dash = new Theme.Btn("Open dashboard", Theme.Btn.Style.GHOST);
        dash.addActionListener(e -> openDashboard());
        Theme.Btn folder = new Theme.Btn("Reports folder", Theme.Btn.Style.GHOST);
        folder.addActionListener(e -> openReportsFolder());
        dockerPill.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) { refreshDocker(); }
        });
        actions.add(dockerPill);
        actions.add(dash);
        actions.add(folder);
        header.add(actions, BorderLayout.EAST);
        return header;
    }

    private JComponent buildBody() {
        JPanel body = new JPanel(new BorderLayout(20, 0));
        body.setOpaque(false);
        body.setBorder(new EmptyBorder(20, 24, 8, 24));

        JPanel left = stack();
        addRow(left, buildSampleCard(), 0);
        addRow(left, buildProfileCard(), 16);
        addFiller(left);
        JPanel leftWrap = new JPanel(new BorderLayout());
        leftWrap.setOpaque(false);
        leftWrap.setPreferredSize(new Dimension(340, 10));
        leftWrap.add(left, BorderLayout.CENTER);

        JPanel right = stack();
        JComponent verdict = buildVerdictCard();
        verdict.setMinimumSize(new Dimension(0, 226));
        addRow(right, verdict, 0);
        JComponent activity = buildActivityCard();
        activity.setPreferredSize(new Dimension(10, 240));
        activity.setMinimumSize(new Dimension(0, 0));
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0; gc.gridy = 1; gc.weightx = 1; gc.weighty = 1; gc.fill = GridBagConstraints.BOTH;
        gc.insets = new Insets(16, 0, 0, 0);
        right.add(activity, gc);
        right.setMinimumSize(new Dimension(0, 0));

        body.add(leftWrap, BorderLayout.WEST);
        body.add(right, BorderLayout.CENTER);
        return body;
    }

    private JComponent buildSampleCard() {
        Theme.Card card = new Theme.Card();
        card.setLayout(new BorderLayout());
        JPanel inner = stack();
        addRow(inner, label("Sample", Theme.head(15f), Theme.TEXT), 0);

        sampleBody.setOpaque(false);
        sampleBody.add(dropZone, "empty");
        sampleBody.add(buildLoadedPanel(), "loaded");
        addRow(inner, sampleBody, 12);

        analyzeBtn.setEnabled(false);
        analyzeBtn.addActionListener(e -> startAnalysis());
        JPanel btnWrap = new JPanel(new BorderLayout());
        btnWrap.setOpaque(false);
        btnWrap.add(analyzeBtn, BorderLayout.CENTER);
        addRow(inner, btnWrap, 16);

        progress.setVisible(false);
        addRow(inner, progress, 10);
        card.add(inner, BorderLayout.NORTH);
        return card;
    }

    private JComponent buildLoadedPanel() {
        JPanel p = stack();
        addRow(p, nameLabel, 0);
        addRow(p, metaLabel, 2);
        JPanel hashRow = new JPanel(new BorderLayout(8, 0));
        hashRow.setOpaque(false);
        hashRow.add(label("SHA-256", Theme.ui(Font.PLAIN, 12f), Theme.MUTED), BorderLayout.WEST);
        hashRow.add(hashLabel, BorderLayout.CENTER);
        copyHashBtn.setFont(Theme.head(12f));
        copyHashBtn.addActionListener(e -> copyToClipboard(sample != null ? sample.sha256() : "", "SHA-256 copied"));
        hashRow.add(copyHashBtn, BorderLayout.EAST);
        addRow(p, hashRow, 16);
        addRow(p, warnLabel, 8);
        Theme.Btn other = new Theme.Btn("Choose a different file", Theme.Btn.Style.LINK);
        other.setFont(Theme.head(12.5f));
        other.addActionListener(e -> chooseFile());
        JPanel otherWrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        otherWrap.setOpaque(false);
        otherWrap.add(other);
        addRow(p, otherWrap, 12);
        return p;
    }

    private JComponent buildProfileCard() {
        Theme.Card card = new Theme.Card();
        card.setLayout(new BorderLayout());
        JPanel inner = stack();
        addRow(inner, label("Sandbox profile", Theme.head(15f), Theme.TEXT), 0);
        String[][] rows = {
                {"Network", "Disabled"},
                {"Memory", "512 MB, no swap"},
                {"CPU", "1 core"},
                {"Processes", "128 max"},
                {"Filesystem", "Read-only"},
                {"Privileges", "Non-root, no capabilities"},
                {"Time limit", DockerOrchestrator.TIMEOUT_SECONDS + " s"}};
        for (String[] r : rows) {
            JPanel row = new JPanel(new BorderLayout());
            row.setOpaque(false);
            row.add(label(r[0], Theme.ui(Font.PLAIN, 13f), Theme.MUTED), BorderLayout.WEST);
            JLabel v = label(r[1], Theme.ui(Font.PLAIN, 13f), Theme.TEXT);
            v.setHorizontalAlignment(JLabel.RIGHT);
            row.add(v, BorderLayout.CENTER);
            addRow(inner, row, 10);
        }
        card.add(inner, BorderLayout.NORTH);
        return card;
    }

    private JComponent buildVerdictCard() {
        Theme.Card card = new Theme.Card(24, Theme.PANEL);
        card.setBorder(new EmptyBorder(14, 14, 18, 24));
        card.setLayout(new BorderLayout(14, 0));
        JPanel towerWrap = new JPanel(new BorderLayout());
        towerWrap.setOpaque(false);
        towerWrap.setPreferredSize(new Dimension(88, 10));
        towerWrap.add(tower, BorderLayout.NORTH);
        card.add(towerWrap, BorderLayout.WEST);

        verdictSub.setLineWrap(true);
        verdictSub.setWrapStyleWord(true);
        verdictSub.setEditable(false);
        verdictSub.setFocusable(false);
        verdictSub.setOpaque(false);
        verdictSub.setForeground(Theme.TEXT);
        verdictSub.setFont(Theme.ui(Font.PLAIN, 14f));
        verdictSub.setBorder(null);
        verdictSub.setRows(2);

        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        JPanel tagWrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        tagWrap.setOpaque(false);
        tagWrap.add(verdictTag);
        top.add(tagWrap, BorderLayout.WEST);
        top.add(scoreText, BorderLayout.EAST);

        JPanel text = stack();
        addRow(text, top, 0);
        addRow(text, verdictSub, 8);
        addRow(text, gauge, 10);
        chips.setOpaque(false);
        addRow(text, chips, 6);
        card.add(text, BorderLayout.CENTER);
        return card;
    }

    private JComponent buildActivityCard() {
        Theme.Card card = new Theme.Card();
        card.setBorder(new EmptyBorder(6, 16, 16, 16));
        card.setLayout(new BorderLayout(0, 12));

        JPanel bar = new JPanel(new BorderLayout());
        bar.setOpaque(false);
        JPanel tabs = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        tabs.setOpaque(false);
        activityTab.addActionListener(e -> showTab(true));
        findingsTab.addActionListener(e -> showTab(false));
        tabs.add(activityTab);
        tabs.add(Box.createHorizontalStrut(26));
        tabs.add(findingsTab);
        bar.add(tabs, BorderLayout.WEST);

        JPanel tools = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 7));
        tools.setOpaque(false);
        tools.add(label("Show system calls", Theme.ui(Font.PLAIN, 12.5f), Theme.MUTED));
        tools.add(verboseToggle);
        tools.add(Box.createHorizontalStrut(6));
        Theme.Btn copy = new Theme.Btn("Copy log", Theme.Btn.Style.LINK);
        copy.setFont(Theme.head(12.5f));
        copy.addActionListener(e -> copyToClipboard(console.getText(), "Log copied"));
        tools.add(copy);
        bar.add(tools, BorderLayout.EAST);
        card.add(bar, BorderLayout.NORTH);

        console.setEditable(false);
        console.setOpaque(false);
        console.setFont(Theme.mono(Font.PLAIN, 12.5f));
        console.setBorder(new EmptyBorder(14, 16, 14, 16));
        console.setCaretColor(Theme.CONSOLE);
        console.setSelectionColor(new Color(0x2C6B5E));
        console.setSelectedTextColor(Color.WHITE);
        console.setTransferHandler(null);
        JScrollPane consoleScroll = new JScrollPane(console);
        consoleScroll.setBorder(null);
        consoleScroll.setOpaque(false);
        consoleScroll.getViewport().setOpaque(false);
        consoleScroll.getViewport().setScrollMode(javax.swing.JViewport.SIMPLE_SCROLL_MODE);
        Theme.slimScroll(consoleScroll.getVerticalScrollBar(), true);
        consoleScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        JScrollPane findingsScroll = new JScrollPane(findingsList);
        findingsScroll.setBorder(null);
        findingsScroll.setOpaque(false);
        findingsScroll.getViewport().setOpaque(false);
        Theme.slimScroll(findingsScroll.getVerticalScrollBar(), false);
        findingsScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        content.setOpaque(false);

        Theme.Chamber chamber = new Theme.Chamber();
        chamber.add(consoleScroll, BorderLayout.CENTER);
        content.removeAll();
        content.add(chamber, "activity");
        content.add(findingsScroll, "findings");
        card.add(content, BorderLayout.CENTER);
        return card;
    }

    private JComponent buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setOpaque(false);
        bar.setBorder(new EmptyBorder(6, 24, 12, 24));
        bar.add(statusLabel, BorderLayout.WEST);
        JLabel where = label("Reports: " + AmasHome.reports(), Theme.ui(Font.PLAIN, 12f), Theme.DIM);
        where.setHorizontalAlignment(JLabel.RIGHT);
        bar.add(where, BorderLayout.EAST);
        return bar;
    }

    // ------------------------------------------------------------------ behaviour

    private void chooseFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose a sample to analyze");
        if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) loadFile(chooser.getSelectedFile());
    }

    void loadFile(File file) {
        setStatus("Reading " + file.getName() + "...");
        new Thread(() -> {
            try {
                SampleIntake.SampleInfo info = SampleIntake.inspect(file.getAbsolutePath());
                SwingUtilities.invokeLater(() -> setSample(info));
            } catch (IOException ex) {
                SwingUtilities.invokeLater(() -> {
                    onEvent(LogEvent.of(LogEvent.Kind.ERROR, "Couldn't read " + file.getName() + ": " + ex.getMessage()));
                    setStatus("Couldn't read the file");
                });
            }
        }, "amas-intake").start();
    }

    void setSample(SampleIntake.SampleInfo info) {
        this.sample = info;
        nameLabel.setText(info.name());
        nameLabel.setToolTipText(info.path().toString());
        metaLabel.setText(info.typeLabel() + "  \u00b7  " + SampleIntake.humanSize(info.size()));
        hashLabel.setText(info.sha256().substring(0, 8) + "\u2026" + info.sha256().substring(56));
        hashLabel.setToolTipText(info.sha256());
        warnLabel.setText(info.supported() ? "" : "<html><body style='width:280px'>" + info.unsupportedReason() + "</body></html>");
        sampleCards.show(sampleBody, "loaded");
        analyzeBtn.setEnabled(info.supported() && !running);
        resetVerdict();
        onEvent(LogEvent.of(LogEvent.Kind.SYSTEM, "Loaded " + info.name() + "  (" + info.typeLabel() + ")"));
        onEvent(LogEvent.of(LogEvent.Kind.SYSTEM, "SHA-256 " + info.sha256()));
        if (!info.supported()) onEvent(LogEvent.of(LogEvent.Kind.ERROR, info.unsupportedReason()));
        setStatus(info.supported() ? "Ready to analyze" : "This file type can't be analyzed here");
    }

    private void startAnalysis() {
        if (sample == null || running) return;
        running = true;
        analyzeBtn.setText("Analyzing\u2026");
        analyzeBtn.setEnabled(false);
        progress.run(true);
        events.clear();
        console.setText("");
        showTab(true);
        tower.off();
        gauge.setIdle();
        scoreText.setOverride(null);
        verdictTag.set("Analyzing\u2026", Theme.RAISED, Theme.TEXT);
        verdictSub.setText("Running " + sample.name() + " in a disposable container.");
        chips.removeAll();
        chips.repaint();
        runStarted = System.currentTimeMillis();
        Timer tick = new Timer(1000, null);
        tick.addActionListener(e -> {
            if (!running) { tick.stop(); return; }
            setStatus("Analyzing\u2026 " + (System.currentTimeMillis() - runStarted) / 1000 + " s");
        });
        tick.start();

        final SampleIntake.SampleInfo target = sample;
        new Thread(() -> {
            Analysis result = DockerOrchestrator.run(target, ev -> SwingUtilities.invokeLater(() -> onEvent(ev)));
            SwingUtilities.invokeLater(() -> finishAnalysis(result));
        }, "amas-analysis").start();
    }

    private void finishAnalysis(Analysis a) {
        running = false;
        last = a;
        progress.run(false);
        analyzeBtn.setText("Analyze again");
        analyzeBtn.setEnabled(sample != null && sample.supported());
        applyAnalysis(a);
        refreshDocker();
    }

    /** Updates the verdict card and findings tab from a finished analysis. */
    void applyAnalysis(Analysis a) {
        last = a;
        chips.removeAll();
        findingsList.removeAll();

        if (a.failed) {
            tower.off();
            gauge.setIdle();
            scoreText.setOverride("!");
            verdictTag.set("Analysis failed", Theme.WARN, Theme.TEXT);
            verdictSub.setText(a.error.split("\n")[0]);
            findingsTab.setText("Findings");
            addFindingsMessage("The sandbox couldn't run, so there is no verdict. This says nothing about the sample.", Theme.WARN);
            setStatus("Analysis failed");
        } else {
            Color c = Theme.forLevel(a.level);
            tower.setLevel(levelIndex(a.level));
            gauge.setScore(a.score);
            scoreText.setOverride(null);
            verdictTag.set(a.level.label, c, Theme.onTone(c));
            verdictSub.setText(summarize(a));
            chips.add(new Chip(a.iocProcesses.size() + (a.iocProcesses.size() == 1 ? " child process" : " child processes"), Theme.AMBER));
            chips.add(new Chip(a.iocFiles.size() + (a.iocFiles.size() == 1 ? " file" : " files"), Theme.BLUE));
            chips.add(new Chip(a.iocNetwork.size() + " network", Theme.VIOLET));
            chips.add(new Chip("exit " + (a.timedOut ? "-" : String.valueOf(a.exitCode)), Theme.MUTED));

            findingsTab.setText("Findings (" + a.findings.size() + ")");
            if (a.findings.isEmpty()) {
                addFindingsMessage("No findings. Nothing suspicious was observed during this run.", Theme.OK);
            }
            for (Analysis.Finding f : a.findings) addFinding(f);
            for (String n : a.notes) addNote(n);
            setStatus("Done. " + DockerOrchestrator.describe(a));
        }
        addFiller(findingsList);
        chips.revalidate();
        chips.repaint();
        findingsList.revalidate();
        SwingUtilities.invokeLater(findingsList::revalidate);
    }

    private static int levelIndex(Analysis.Level l) {
        return switch (l) { case CLEAN -> 0; case SUSPICIOUS -> 1; case LIKELY_MALICIOUS -> 2; case MALICIOUS -> 3; default -> -1; };
    }

    /** One plain-English sentence about what the sample did, built from the findings. */
    private static String summarize(Analysis a) {
        List<String> parts = new ArrayList<>();
        for (Analysis.Finding f : a.findings) {
            switch (f.id()) {
                case "escape" -> parts.add("probed for a way out of the sandbox");
                case "persistence" -> parts.add("tried to make itself run again later");
                case "sensitive-files" -> parts.add("read credential or system files");
                case "network" -> parts.add("tried to reach the network");
                case "net-tools" -> parts.add("ran download or remote-access tools");
                case "listener" -> parts.add("opened a listening port");
                case "hidden-files" -> parts.add("created hidden files");
                case "fs-write" -> parts.add("wrote outside its temp folder");
                case "fs-tamper" -> parts.add("deleted or changed files");
                case "timeout" -> parts.add("ran past the time limit");
                case "killed" -> parts.add("was stopped by the system");
                case "children" -> parts.add("started " + a.iocProcesses.size() + " other program" + (a.iocProcesses.size() == 1 ? "" : "s"));
                default -> {}
            }
        }
        if (parts.isEmpty()) return "Nothing suspicious happened while it ran.";
        String joined = parts.size() == 1 ? parts.get(0)
                : String.join(", ", parts.subList(0, parts.size() - 1)) + " and " + parts.get(parts.size() - 1);
        long acts = a.events.stream().filter(e -> !e.type().equals("process")).count();
        long blocked = a.events.stream().filter(e -> !e.type().equals("process") && e.blocked()).count();
        return "It " + joined + "." + (blocked > 0 ? " The sandbox blocked " + blocked + " of " + acts + " file and network actions." : "");
    }

    private void resetVerdict() {
        tower.off();
        gauge.setIdle();
        scoreText.setOverride(null);
        verdictTag.set(sample == null ? "Ready" : "Ready to analyze", Theme.RAISED, Theme.MUTED);
        verdictSub.setText(sample == null ? "Choose a sample to begin."
                : "Select Analyze to run it in the sandbox.");
        chips.removeAll();
        chips.repaint();
        findingsList.removeAll();
        addFindingsMessage("Findings appear here after an analysis.", Theme.MUTED);
        addFiller(findingsList);
        findingsTab.setText("Findings");
    }

    // -- console

    void onEvent(LogEvent e) {
        if (events.size() >= MAX_EVENTS) return;
        events.add(e);
        if (!e.isNoise() || verboseToggle.isOn()) append(e);
    }

    private void refilter() {
        console.setText("");
        for (LogEvent e : events) if (!e.isNoise() || verboseToggle.isOn()) append(e);
    }

    private void append(LogEvent e) {
        StyledDocument doc = console.getStyledDocument();
        try {
            String time = LocalTime.ofInstant(Instant.ofEpochMilli(e.timestamp()), ZoneId.systemDefault()).format(CLOCK);
            int lineStart = doc.getLength();
            float indent = console.getFontMetrics(Theme.mono(Font.PLAIN, 12f)).charWidth('0') * 17f;
            doc.insertString(doc.getLength(), time + "  ", style(Theme.CON_DIM, false));
            doc.insertString(doc.getLength(), String.format("%-5s", tag(e.kind())) + "  ", style(Theme.forKind(e.kind()), true));
            Color body = switch (e.kind()) {
                case TRACE -> Theme.CON_DIM;
                case OUTPUT -> Theme.CON_TEXT;
                case SYSTEM -> Theme.CON_MUTED;
                default -> Theme.forKind(e.kind());
            };
            int start = lineStart;
            doc.insertString(doc.getLength(), e.text() + "\n", style(e.kind() == LogEvent.Kind.SYSTEM ? Theme.CON_MUTED : body, false));
            SimpleAttributeSet para = new SimpleAttributeSet();
            StyleConstants.setLeftIndent(para, indent);
            StyleConstants.setFirstLineIndent(para, -indent);
            doc.setParagraphAttributes(start, doc.getLength() - start, para, false);
            console.setCaretPosition(doc.getLength());
        } catch (BadLocationException ignored) {}
    }

    private static SimpleAttributeSet style(Color c, boolean bold) {
        SimpleAttributeSet s = new SimpleAttributeSet();
        StyleConstants.setForeground(s, c);
        StyleConstants.setBold(s, bold);
        StyleConstants.setFontFamily(s, Theme.mono(Font.PLAIN, 12f).getFamily());
        StyleConstants.setFontSize(s, 12);
        return s;
    }

    private static String tag(LogEvent.Kind k) {
        return switch (k) {
            case SYSTEM -> "SYS";
            case SUCCESS -> "OK";
            case WARN -> "WARN";
            case ERROR -> "ERR";
            case OUTPUT -> "OUT";
            case EXEC -> "EXEC";
            case FILE -> "FILE";
            case NET -> "NET";
            case TRACE -> "TRACE";
        };
    }

    // -- findings

    private void addFinding(Analysis.Finding f) {
        final Color sev = Theme.forSeverity(f.severity());
        JPanel row = new JPanel(new BorderLayout(14, 0)) {
            @Override protected void paintComponent(Graphics g) {
                g.setColor(Theme.LINE);
                g.fillRect(0, getHeight() - 1, getWidth(), 1);
            }
        };
        row.setOpaque(false);
        row.setBorder(new EmptyBorder(12, 2, 12, 2));
        JComponent badge = new JComponent() {
            { setPreferredSize(new Dimension(50, 46)); }
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = Theme.smooth(g);
                boolean info = f.severity().equals("info");
                Color bg = info ? Theme.RAISED : sev;
                g2.setColor(Theme.mix(bg, Color.BLACK, 0.82));
                g2.fill(new RoundRectangle2D.Float(0, 0, 50, 46, 14, 14));
                g2.setColor(bg);
                g2.fill(new RoundRectangle2D.Float(0, 0, 50, 43, 14, 14));
                g2.setFont(Theme.display(15f));
                g2.setColor(info ? Theme.MUTED : Theme.onTone(bg));
                String t = "+" + f.points();
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(t, (50 - fm.stringWidth(t)) / 2, (43 - fm.getHeight()) / 2 + fm.getAscent());
                g2.dispose();
            }
        };
        JPanel badgeWrap = new JPanel(new BorderLayout());
        badgeWrap.setOpaque(false);
        badgeWrap.add(badge, BorderLayout.NORTH);
        row.add(badgeWrap, BorderLayout.WEST);
        JPanel text = stack();
        addRow(text, label(f.title(), Theme.ui(Font.BOLD, 14f), Theme.TEXT), 0);
        JTextArea detail = new JTextArea(f.detail());
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        detail.setEditable(false);
        detail.setFocusable(false);
        detail.setOpaque(false);
        detail.setForeground(Theme.MUTED);
        detail.setFont(Theme.mono(Font.PLAIN, 12f));
        detail.setBorder(null);
        addRow(text, detail, 3);
        row.add(text, BorderLayout.CENTER);
        addRow(findingsList, row, 0);
    }

    private void addNote(String note) {
        JTextArea t = new JTextArea(note);
        t.setLineWrap(true);
        t.setWrapStyleWord(true);
        t.setEditable(false);
        t.setFocusable(false);
        t.setOpaque(false);
        t.setForeground(Theme.MUTED);
        t.setFont(Theme.ui(Font.PLAIN, 12f));
        t.setBorder(new EmptyBorder(0, 6, 0, 6));
        addRow(findingsList, t, 12);
    }

    private void addFindingsMessage(String text, Color color) {
        JLabel l = label(text, Theme.ui(Font.PLAIN, 13f), color);
        l.setBorder(new EmptyBorder(12, 8, 0, 8));
        addRow(findingsList, l, 0);
    }

    void showTab(boolean activity) {
        activityTab.setSelectedTab(activity);
        findingsTab.setSelectedTab(!activity);
        contentCards.show(content, activity ? "activity" : "findings");
    }

    // -- docker + dashboard

    private void refreshDocker() {
        dockerPill.set(Theme.MUTED, "Checking Docker\u2026");
        new Thread(() -> {
            String v = DockerOrchestrator.dockerVersion();
            SwingUtilities.invokeLater(() -> {
                if (v != null) dockerPill.set(Theme.OK, "Docker " + v);
                else dockerPill.set(Theme.DANGER, "Docker not running");
            });
        }, "amas-docker-check").start();
    }

    private void openReportsFolder() {
        try {
            Desktop.getDesktop().open(AmasHome.reports().toFile());
        } catch (Exception e) {
            setStatus("Couldn't open " + AmasHome.reports());
        }
    }

    private void openDashboard() {
        setStatus("Opening the dashboard\u2026");
        new Thread(() -> {
            try {
                if (!portOpen()) startDashboard();
                if (portOpen()) {
                    Desktop.getDesktop().browse(URI.create("http://127.0.0.1:" + DASHBOARD_PORT + "/"));
                    SwingUtilities.invokeLater(() -> setStatus("Dashboard opened in your browser"));
                } else {
                    SwingUtilities.invokeLater(() -> {
                        onEvent(LogEvent.of(LogEvent.Kind.ERROR,
                                "The dashboard didn't start. Install its one dependency with: pip install -r dashboard/requirements.txt"));
                        setStatus("Dashboard unavailable");
                    });
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> setStatus("Couldn't open the dashboard: " + e.getMessage()));
            }
        }, "amas-dashboard").start();
    }

    private void startDashboard() throws InterruptedException {
        String script = AmasHome.dashboardScript().toString();
        String[][] candidates = {{"python", script}, {"python3", script}, {"py", "-3", script}};
        for (String[] cmd : candidates) {
            try {
                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.directory(AmasHome.dashboardScript().getParent().toFile());
                pb.environment().put("AMAS_REPORTS", AmasHome.reports().toString());
                pb.redirectErrorStream(true);
                pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                Process p = pb.start();
                for (int i = 0; i < 40; i++) {
                    Thread.sleep(200);
                    if (portOpen()) { dashboardProcess = p; return; }
                    if (!p.isAlive()) break;
                }
                p.destroy();
            } catch (IOException ignored) {
                // interpreter not found, try the next candidate
            }
        }
    }

    private static boolean portOpen() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", DASHBOARD_PORT), 250);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void shutdown() {
        if (dashboardProcess != null) dashboardProcess.destroy();
        DockerOrchestrator.killActive();
    }

    // -- drag and drop, shortcuts, misc

    private void installDragAndDrop(JComponent root) {
        TransferHandler handler = new TransferHandler() {
            @Override public boolean canImport(TransferSupport s) { return s.isDataFlavorSupported(DataFlavor.javaFileListFlavor); }
            @Override public boolean importData(TransferSupport s) {
                if (!canImport(s)) return false;
                try {
                    @SuppressWarnings("unchecked")
                    List<File> files = (List<File>) s.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!files.isEmpty() && !running) loadFile(files.get(0));
                    return true;
                } catch (Exception e) {
                    return false;
                }
            }
        };
        root.setTransferHandler(handler);
        dropZone.setTransferHandler(handler);
        console.setTransferHandler(handler);
    }

    private void installShortcuts(JComponent root) {
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_O, Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()), "open");
        root.getActionMap().put("open", new javax.swing.AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { if (!running) chooseFile(); }
        });
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()), "analyze");
        root.getActionMap().put("analyze", new javax.swing.AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { if (analyzeBtn.isEnabled()) startAnalysis(); }
        });
    }

    private void copyToClipboard(String text, String status) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        setStatus(status);
    }

    private void setStatus(String text) { statusLabel.setText(text); }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    // ------------------------------------------------------------------ layout helpers

    static JLabel label(String text, Font font, Color color) {
        JLabel l = new JLabel(text);
        l.setFont(font);
        l.setForeground(color);
        l.setMinimumSize(new Dimension(0, 0));
        return l;
    }

    static JPanel stack() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setOpaque(false);
        return p;
    }

    static void addRow(JPanel p, Component c, int topGap) {
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0;
        gc.gridy = p.getComponentCount();
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.NORTHWEST;
        gc.insets = new Insets(topGap, 0, 0, 0);
        p.add(c, gc);
    }

    static void addFiller(JPanel p) {
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0;
        gc.gridy = p.getComponentCount();
        gc.weighty = 1;
        gc.fill = GridBagConstraints.VERTICAL;
        p.add(Box.createGlue(), gc);
    }

    // ------------------------------------------------------------------ small components

    /** Scroll content that always matches the viewport width so wrapped text reflows. */
    private static final class ScrollPanel extends JPanel implements Scrollable {
        ScrollPanel() {
            super(new GridBagLayout());
            setOpaque(false);
            setBorder(new EmptyBorder(6, 8, 8, 8));
        }
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int o, int d) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int o, int d) { return 64; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }

    /** "Docker 27.3.1" style status indicator in the header. */
    private static final class StatusPill extends JComponent {
        private Color dot = Theme.MUTED;
        private String text = "Checking Docker\u2026";

        StatusPill() { setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR)); }

        void set(Color c, String t) { dot = c; text = t; revalidate(); repaint(); }

        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(Theme.ui(Font.PLAIN, 12f));
            return new Dimension(fm.stringWidth(text) + 40, 30);
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.smooth(g);
            g2.setColor(Theme.PANEL);
            g2.fill(new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1, getHeight() - 1, 30, 30));
            g2.setColor(Theme.LINE);
            g2.draw(new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1, getHeight() - 1, 30, 30));
            g2.setColor(Theme.alpha(dot, 60));
            g2.fillOval(9, getHeight() / 2 - 8, 16, 16);
            g2.setColor(dot);
            g2.fillOval(13, getHeight() / 2 - 4, 8, 8);
            g2.setFont(Theme.ui(Font.PLAIN, 12f));
            g2.setColor(Theme.TEXT);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(text, 28, (getHeight() - fm.getHeight()) / 2 + fm.getAscent());
            g2.dispose();
        }
    }

    /** Small counter pill under the verdict, coloured to match the event type in the activity feed. */
    private static final class Chip extends JComponent {
        private final String text;
        private final Color dot;

        Chip(String text, Color dot) { this.text = text; this.dot = dot; }

        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(Theme.ui(Font.PLAIN, 12f));
            return new Dimension(fm.stringWidth(text) + 34, 28);
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.smooth(g);
            g2.setColor(Theme.RAISED);
            g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 14, 14));
            g2.setColor(dot);
            g2.fillOval(12, getHeight() / 2 - 3, 6, 6);
            g2.setColor(Theme.TEXT);
            g2.setFont(Theme.ui(Font.PLAIN, 12f));
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(text, 24, (getHeight() - fm.getHeight()) / 2 + fm.getAscent());
            g2.dispose();
        }
    }

    /** Dashed drop target shown until a sample is chosen. */
    private final class DropZone extends JPanel {
        DropZone() {
            super(new GridBagLayout());
            setOpaque(false);
            setPreferredSize(new Dimension(10, 156));
            GridBagConstraints gc = new GridBagConstraints();
            gc.gridx = 0;
            gc.insets = new Insets(0, 0, 0, 0);
            gc.gridy = 0; add(new Glyph(), gc);
            gc.gridy = 1; gc.insets = new Insets(10, 0, 0, 0);
            add(label("Drop a file here", Theme.head(15f), Theme.TEXT), gc);
            gc.gridy = 2; gc.insets = new Insets(2, 0, 0, 0);
            add(label("Shell, Python, JavaScript or Linux binary", Theme.ui(Font.PLAIN, 12f), Theme.MUTED), gc);
            Theme.Btn choose = new Theme.Btn("Choose file\u2026", Theme.Btn.Style.LINK);
            choose.setFont(Theme.head(13f));
            choose.addActionListener(e -> chooseFile());
            gc.gridy = 3; gc.insets = new Insets(6, 0, 0, 0);
            add(choose, gc);
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.smooth(g);
            g2.setColor(Theme.alpha(Theme.RAISED, 120));
            g2.fill(new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1, getHeight() - 1, 16, 16));
            g2.setColor(Theme.MUTED);
            g2.setStroke(new BasicStroke(1.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 1f, new float[] {5f, 5f}, 0f));
            g2.draw(new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1, getHeight() - 1, 16, 16));
            g2.dispose();
        }
    }

    /** Small document outline used in the empty drop zone. */
    private static final class Glyph extends JComponent {
        Glyph() { setPreferredSize(new Dimension(30, 36)); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.smooth(g);
            g2.setColor(Theme.MUTED);
            g2.setStroke(new BasicStroke(1.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            Path2D doc = new Path2D.Float();
            doc.moveTo(4, 2);
            doc.lineTo(19, 2);
            doc.lineTo(26, 9);
            doc.lineTo(26, 33);
            doc.lineTo(4, 33);
            doc.closePath();
            g2.draw(doc);
            Path2D fold = new Path2D.Float();
            fold.moveTo(19, 2);
            fold.lineTo(19, 9);
            fold.lineTo(26, 9);
            g2.draw(fold);
            g2.setColor(Theme.BRAND);
            g2.drawLine(15, 27, 15, 16);
            g2.drawLine(15, 16, 11, 20);
            g2.drawLine(15, 16, 19, 20);
            g2.dispose();
        }
    }
}
