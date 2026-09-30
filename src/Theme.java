import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.Timer;
import javax.swing.plaf.basic.BasicScrollBarUI;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.Insets;
import java.awt.RadialGradientPaint;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Arc2D;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Design tokens and the small set of custom-painted widgets the desktop app is built from. */
final class Theme {

    // Palette: "bench". A bone-grey lab bench, ink-black controls, safety-orange brand, and a dark
    // pine-glass chamber for anything live (the console). Verdict colours follow a stack light.
    static final Color BG = new Color(0xE3E6E1);
    static final Color PANEL = new Color(0xF3F4F0);
    static final Color RAISED = new Color(0xD6DAD3);
    static final Color LINE = new Color(0xC5CBC4);
    static final Color TEXT = new Color(0x13171A);
    static final Color MUTED = new Color(0x5B6660);
    static final Color DIM = new Color(0x8A948E);
    static final Color ACCENT = new Color(0x13171A);          // primary buttons are ink
    static final Color ACCENT_HOVER = new Color(0x2C3338);
    static final Color BRAND = new Color(0xFF5A1F);           // safety orange: logo, selection, live things
    static final Color BRAND_DARK = new Color(0xD9430C);

    static final Color OK = new Color(0x17B26A);
    static final Color WARN = new Color(0xF5B400);
    static final Color ORANGE = new Color(0xF5701E);
    static final Color DANGER = new Color(0xE5222D);
    static final Color LOW = new Color(0x9CCFC1);
    static final Color VIOLET = new Color(0xFF6E8A);          // network events (coral on the chamber)
    static final Color BLUE = new Color(0x4FD8E8);            // file events (cyan on the chamber)
    static final Color AMBER = new Color(0xFFB020);           // process events

    // The chamber: tinted pine glass with light text.
    static final Color CONSOLE = new Color(0x0E2A25);
    static final Color CON_TEXT = new Color(0xE6F4EE);
    static final Color CON_MUTED = new Color(0x9DB8AF);
    static final Color CON_DIM = new Color(0x6E8C84);

    private static final Set<String> FAMILIES = new HashSet<>(Arrays.asList(
            GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames()));

    private static final String UI_FAMILY = pick("Segoe UI Variable Text", "Segoe UI", "Inter", "SF Pro Text",
            "Helvetica Neue", "Ubuntu", "Noto Sans", "DejaVu Sans", "SansSerif");
    private static final String MONO_FAMILY = pick("Cascadia Mono", "JetBrains Mono", "Consolas", "SF Mono",
            "Menlo", "DejaVu Sans Mono", "Monospaced");

    private Theme() {}

    private static Font loadFont(String file) {
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(AmasHome.root().resolve("assets").resolve("fonts").resolve(file))) {
            return Font.createFont(Font.TRUETYPE_FONT, in);
        } catch (Exception e) {
            return null;
        }
    }
    private static final Font DISPLAY = loadFont("Archivo-DisplayExtraBold.ttf");
    private static final Font HEAD = loadFont("Archivo-HeadBold.ttf");

    /** Wide, heavy face for the verdict, score and wordmark. Latin text only. */
    static Font display(float size) { return DISPLAY != null ? DISPLAY.deriveFont(Font.PLAIN, size) : ui(Font.BOLD, size); }
    /** Bold headline face for card titles and buttons. Latin text only. */
    static Font head(float size) { return HEAD != null ? HEAD.deriveFont(Font.PLAIN, size) : ui(Font.BOLD, size); }

    static Font ui(int style, float size) { return new Font(UI_FAMILY, style, 1).deriveFont(style, size); }
    static Font mono(int style, float size) { return new Font(MONO_FAMILY, style, 1).deriveFont(style, size); }

    private static String pick(String... names) {
        for (String n : names) if (FAMILIES.contains(n)) return n;
        return names[names.length - 1];
    }

    static Color alpha(Color c, int a) { return new Color(c.getRed(), c.getGreen(), c.getBlue(), a); }

    static Graphics2D smooth(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        return g2;
    }

    static Color forLevel(Analysis.Level level) {
        return switch (level) {
            case CLEAN -> OK;
            case SUSPICIOUS -> WARN;
            case LIKELY_MALICIOUS -> ORANGE;
            case MALICIOUS -> DANGER;
            case INCONCLUSIVE -> MUTED;
        };
    }

    static Color forSeverity(String severity) {
        return switch (severity) {
            case "critical" -> DANGER;
            case "high" -> ORANGE;
            case "medium" -> WARN;
            case "low" -> LOW;
            default -> MUTED;
        };
    }

    /** Colours for the dark console. */
    static Color forKind(LogEvent.Kind kind) {
        return switch (kind) {
            case SYSTEM -> CON_MUTED;
            case SUCCESS -> new Color(0x5FE0A5);
            case WARN -> new Color(0xFFC94D);
            case ERROR -> new Color(0xFF7A7A);
            case OUTPUT -> CON_TEXT;
            case EXEC -> AMBER;
            case FILE -> BLUE;
            case NET -> VIOLET;
            case TRACE -> CON_DIM;
        };
    }

    static Color onTone(Color c) {
        double l = (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) / 255.0;
        return l > 0.6 ? TEXT : Color.WHITE;
    }

    /** The app mark: a safety-orange hexagon with an ink lens, like an indicator on lab equipment. */
    static void paintLogo(Graphics2D g, int x, int y, int size) {
        float s = size / 40f;
        Path2D hex = new Path2D.Float();
        hex.moveTo(x + 20 * s, y + 2 * s);
        hex.lineTo(x + 36 * s, y + 11 * s);
        hex.lineTo(x + 36 * s, y + 29 * s);
        hex.lineTo(x + 20 * s, y + 38 * s);
        hex.lineTo(x + 4 * s, y + 29 * s);
        hex.lineTo(x + 4 * s, y + 11 * s);
        hex.closePath();
        g.setPaint(new GradientPaint(x, y, new Color(0xFF7A3D), x, y + size, BRAND));
        g.fill(hex);
        g.setColor(new Color(0, 0, 0, 60));
        g.setStroke(new BasicStroke(1.2f * s));
        g.draw(hex);
        g.setColor(TEXT);
        g.fill(new Ellipse2D.Float(x + 13 * s, y + 13 * s, 14 * s, 14 * s));
        g.setColor(BRAND);
        g.fill(new Ellipse2D.Float(x + 17.4f * s, y + 17.4f * s, 5.2f * s, 5.2f * s));
    }

    static BufferedImage logoImage(int size) {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = smooth(img.getGraphics());
        paintLogo(g, 0, 0, size);
        g.dispose();
        return img;
    }

    static Color mix(Color a, Color b, double t) {
        return new Color(
                (int) Math.round(a.getRed() * t + b.getRed() * (1 - t)),
                (int) Math.round(a.getGreen() * t + b.getGreen() * (1 - t)),
                (int) Math.round(a.getBlue() * t + b.getBlue() * (1 - t)));
    }

    private static RoundRectangle2D rr(double x, double y, double w, double h, double r) {
        return new RoundRectangle2D.Double(x, y, w, h, r, r);
    }

    // ------------------------------------------------------------------ widgets

    /** A light plate: rounded, with a hairline border and a thin highlight along the top edge. */
    static class Card extends JPanel {
        private final int radius;
        private final Color fill;

        Card() { this(20, PANEL); }

        Card(int radius, Color fill) {
            this.radius = radius;
            this.fill = fill;
            setOpaque(false);
            setBorder(BorderFactory.createEmptyBorder(18, 20, 18, 20));
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            g2.setColor(fill);
            g2.fill(rr(0.5, 0.5, getWidth() - 1, getHeight() - 1, radius));
            g2.setColor(new Color(255, 255, 255, 170));
            g2.drawLine(radius / 2, 1, getWidth() - radius / 2, 1);
            g2.setColor(LINE);
            g2.setStroke(new BasicStroke(1f));
            g2.draw(rr(0.5, 0.5, getWidth() - 1, getHeight() - 1, radius));
            g2.dispose();
            super.paintComponent(g);
        }
    }

    /** Dark pine glass with viewfinder corners: the window onto whatever is running. */
    static class Chamber extends JPanel {
        Chamber() {
            super(new java.awt.BorderLayout());
            setOpaque(false);
            setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            g2.setPaint(new RadialGradientPaint(w * 0.5f, h * 0.35f, Math.max(w, h) * 0.8f,
                    new float[] {0f, 0.6f, 1f}, new Color[] {new Color(0x17423A), CONSOLE, new Color(0x071916)}));
            g2.fill(rr(0, 0, w, h, 16));
            g2.dispose();
            super.paintComponent(g);
        }

        @Override protected void paintChildren(Graphics g) {
            super.paintChildren(g);
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight(), m = 12, L = 16;
            g2.setColor(new Color(216, 236, 229, 90));
            g2.setStroke(new BasicStroke(1.6f, BasicStroke.CAP_SQUARE, BasicStroke.JOIN_MITER));
            g2.drawLine(m, m, m + L, m); g2.drawLine(m, m, m, m + L);
            g2.drawLine(w - m, m, w - m - L, m); g2.drawLine(w - m, m, w - m, m + L);
            g2.drawLine(m, h - m, m + L, h - m); g2.drawLine(m, h - m, m, h - m - L);
            g2.drawLine(w - m, h - m, w - m - L, h - m); g2.drawLine(w - m, h - m, w - m, h - m - L);
            g2.setColor(new Color(255, 255, 255, 12));
            Path2D glare = new Path2D.Float();
            glare.moveTo(0, 0); glare.lineTo(w * 0.34f, 0); glare.lineTo(0, h * 0.42f); glare.closePath();
            g2.setClip(rr(0, 0, w, h, 16));
            g2.fill(glare);
            g2.dispose();
        }
    }

    /** Custom-painted button: primary (ink, tactile), ghost (outlined), tab (orange underline) or link. */
    static class Btn extends JButton {
        enum Style { PRIMARY, GHOST, TAB, LINK }

        private final Style style;
        private boolean hover;
        private boolean selected;

        Btn(String text, Style style) {
            super(text);
            this.style = style;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setOpaque(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setFont(style == Style.TAB ? head(14f) : head(13f));
            setMargin(new Insets(0, 0, 0, 0));
            addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e) { hover = true; repaint(); }
                @Override public void mouseExited(MouseEvent e) { hover = false; repaint(); }
            });
        }

        void setSelectedTab(boolean value) { selected = value; repaint(); }

        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            int padX = switch (style) { case PRIMARY -> 26; case GHOST -> 16; case TAB -> 2; case LINK -> 0; };
            int h = switch (style) { case PRIMARY -> 46; case GHOST -> 36; case TAB -> 36; case LINK -> 22; };
            return new Dimension(fm.stringWidth(getText()) + padX * 2, h);
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            boolean on = isEnabled();
            Color textColor;

            switch (style) {
                case PRIMARY -> {
                    if (on) {
                        Color base = hover ? ACCENT_HOVER : ACCENT;
                        g2.setColor(new Color(0, 0, 0, 90));
                        g2.fill(rr(0, 2, w, h - 2, 12));
                        g2.setPaint(new GradientPaint(0, 0, mix(base, Color.WHITE, 0.86), 0, h, base));
                        g2.fill(rr(0, 0, w, h - 3, 12));
                        g2.setColor(new Color(255, 255, 255, 40));
                        g2.drawLine(8, 1, w - 8, 1);
                        textColor = Color.WHITE;
                    } else {
                        g2.setColor(RAISED);
                        g2.fill(rr(0, 0, w, h - 3, 12));
                        textColor = DIM;
                    }
                }
                case GHOST -> {
                    g2.setColor(hover && on ? Color.WHITE : PANEL);
                    g2.fill(rr(0.5, 0.5, w - 1, h - 1, 11));
                    g2.setColor(hover && on ? TEXT : LINE);
                    g2.draw(rr(0.5, 0.5, w - 1, h - 1, 11));
                    textColor = on ? TEXT : DIM;
                }
                case TAB -> {
                    textColor = selected || hover ? TEXT : MUTED;
                    if (selected) {
                        g2.setColor(BRAND);
                        g2.fillRect(0, h - 3, w, 3);
                    }
                }
                default -> textColor = hover ? BRAND_DARK : TEXT;
            }

            g2.setFont(getFont());
            g2.setColor(textColor);
            FontMetrics fm = g2.getFontMetrics();
            int lift = style == Style.PRIMARY ? -1 : 0;
            int ty = (h - fm.getHeight()) / 2 + fm.getAscent() + lift;
            g2.drawString(getText(), (w - fm.stringWidth(getText())) / 2, ty);
            if (style == Style.LINK && hover) g2.drawLine((w - fm.stringWidth(getText())) / 2, ty + 2, (w + fm.stringWidth(getText())) / 2, ty + 2);
            g2.dispose();
        }
    }

    /**
     * The verdict lamp: a four-lamp stack light like the tower on a factory machine. It sweeps up
     * from green to the verdict when a result arrives. Index 0 is green, 3 is red, -1 is all dark.
     */
    static class StackLight extends JComponent {
        private static final Color[] LAMP = {OK, WARN, ORANGE, DANGER};
        private final float[] shown = new float[4];
        private final float[] target = new float[4];
        private final Timer fade;
        private Timer sweep;

        StackLight() {
            setPreferredSize(new Dimension(88, 176));
            fade = new Timer(16, e -> {
                boolean moving = false;
                for (int i = 0; i < 4; i++) {
                    float d = target[i] - shown[i];
                    if (Math.abs(d) > 0.01f) { shown[i] += Math.signum(d) * Math.min(Math.abs(d), 0.28f); moving = true; }
                    else shown[i] = target[i];
                }
                if (!moving) ((Timer) e.getSource()).stop();
                repaint();
            });
        }

        private void light(int only) {
            for (int i = 0; i < 4; i++) target[i] = i == only ? 1f : 0f;
            fade.start();
        }

        void setLevel(int level) {
            if (sweep != null) sweep.stop();
            int top = Math.max(level, 0);
            int[] step = {0};
            sweep = new Timer(150, null);
            sweep.addActionListener(e -> {
                if (step[0] <= top) light(step[0]++);
                else { light(level); sweep.stop(); }
            });
            sweep.setInitialDelay(60);
            sweep.start();
        }

        void off() {
            if (sweep != null) sweep.stop();
            light(-1);
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            double sc = 0.9;
            g2.translate((getWidth() - 64 * sc) / 2, 14);
            g2.scale(sc, sc);
            Color metal = new Color(0xA9B1AB), off = new Color(0xCDD2CB);
            g2.setColor(metal);
            g2.fill(rr(17, 1, 30, 9, 9));
            for (int k = 0; k < 4; k++) {
                int i = 3 - k;
                double y = 11 + k * 35;
                float on = shown[i];
                Color c = LAMP[i];
                if (on > 0.02f) {
                    g2.setPaint(new RadialGradientPaint(32, (float) (y + 16), 42f, new float[] {0f, 1f},
                            new Color[] {new Color(c.getRed(), c.getGreen(), c.getBlue(), (int) (150 * on)), new Color(c.getRed(), c.getGreen(), c.getBlue(), 0)}));
                    g2.fill(new java.awt.geom.Ellipse2D.Double(-10, y - 26, 84, 84));
                }
                g2.setColor(mix(c, mix(c, off, 0.2), on));
                g2.fill(rr(7, y, 50, 32, 16));
                g2.setColor(new Color(255, 255, 255, (int) (50 + 90 * on)));
                g2.setStroke(new BasicStroke(1.4f));
                g2.drawLine(7, (int) y + 11, 57, (int) y + 11);
                g2.drawLine(7, (int) y + 21, 57, (int) y + 21);
                g2.setColor(new Color(255, 255, 255, (int) (70 + 90 * on)));
                g2.fill(rr(13, y + 4, 5, 24, 5));
            }
            g2.setColor(metal);
            g2.fill(rr(3, 151, 58, 12, 8));
            g2.fill(rr(12, 163, 40, 7, 6));
            g2.dispose();
        }
    }

    /** The verdict label: a heavy, wide caption on a coloured plate, like a label-maker strip. */
    static class Tag extends JComponent {
        private String text = "Ready";
        private Color bg = RAISED, fg = MUTED;

        void set(String text, Color bg, Color fg) { this.text = text; this.bg = bg; this.fg = fg; revalidate(); repaint(); }

        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(display(text.length() > 12 ? 19f : 24f));
            return new Dimension(fm.stringWidth(text) + 34, 42);
        }

        @Override public Dimension getMaximumSize() { return getPreferredSize(); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            g2.setColor(mix(bg, Color.BLACK, 0.8));
            g2.fill(rr(0, 0, w, h, 12));
            g2.setColor(bg);
            g2.fill(rr(0, 0, w, h - 3, 12));
            g2.setColor(new Color(255, 255, 255, 80));
            g2.drawLine(8, 1, w - 8, 1);
            g2.setFont(display(text.length() > 12 ? 19f : 24f));
            g2.setColor(fg);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(text, (w - fm.stringWidth(text)) / 2, (h - 3 - fm.getHeight()) / 2 + fm.getAscent());
            g2.dispose();
        }
    }

    /** Segmented risk gauge (clean / suspicious / likely / malicious) with a needle that sweeps to the score. */
    static class Gauge extends JComponent {
        private static final int[][] BOUNDS = {{0, 15}, {15, 40}, {40, 70}, {70, 100}};
        private static final Color[] COL = {OK, WARN, ORANGE, DANGER};
        private static final String[] NAMES = {"Clean", "Suspicious", "Likely", "Malicious"};
        private double shown;
        private int target;
        private boolean has;
        private Timer anim;
        private Runnable onTick = () -> {};

        Gauge() { setPreferredSize(new Dimension(10, 54)); }

        void onTick(Runnable r) { onTick = r; }
        double shown() { return shown; }
        boolean hasScore() { return has; }

        void setIdle() {
            if (anim != null) anim.stop();
            has = false; shown = 0; target = 0; onTick.run(); repaint();
        }

        void setScore(int score) {
            if (anim != null) anim.stop();
            has = true; target = Math.max(0, Math.min(100, score)); shown = 0;
            anim = new Timer(16, e -> {
                shown += Math.max(0.8, (target - shown) * 0.1);
                if (shown >= target) { shown = target; anim.stop(); }
                onTick.run();
                repaint();
            });
            anim.start();
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), gap = 3, top = 12, th = 16;
            double usable = w - gap * 3;
            double x = 0;
            g2.setFont(ui(Font.PLAIN, 11f));
            FontMetrics fm = g2.getFontMetrics();
            for (int i = 0; i < 4; i++) {
                int a = BOUNDS[i][0], b = BOUNDS[i][1];
                double sw = usable * (b - a) / 100.0;
                Shape seg = rr(x, top, sw, th, 8);
                g2.setColor(mix(COL[i], RAISED, 0.22));
                g2.fill(seg);
                double frac = has ? Math.max(0, Math.min(1, (shown - a) / (double) (b - a))) : 0;
                if (frac > 0) {
                    java.awt.Shape old = g2.getClip();
                    g2.clip(seg);
                    g2.setColor(COL[i]);
                    g2.fill(new java.awt.geom.Rectangle2D.Double(x, top, sw * frac, th));
                    g2.setClip(old);
                }
                g2.setColor(MUTED);
                g2.drawString(NAMES[i], (float) x, top + th + 15);
                x += sw + gap;
            }
            if (has) {
                double nx = shown / 100.0 * w;
                Path2D tri = new Path2D.Double();
                tri.moveTo(nx - 6, 0); tri.lineTo(nx + 6, 0); tri.lineTo(nx, 9); tri.closePath();
                g2.setColor(TEXT);
                g2.fill(tri);
            }
            g2.dispose();
        }
    }

    /** The big score number, driven by the gauge so it counts up with the needle. */
    static class ScoreText extends JComponent {
        private final Gauge gauge;
        private String override;

        ScoreText(Gauge gauge) {
            this.gauge = gauge;
            setPreferredSize(new Dimension(120, 44));
            gauge.onTick(this::repaint);
        }

        void setOverride(String s) { override = s; repaint(); }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            String big = override != null ? override : gauge.hasScore() ? String.valueOf((int) Math.round(gauge.shown())) : "-";
            g2.setFont(display(36f));
            FontMetrics bm = g2.getFontMetrics();
            g2.setFont(ui(Font.BOLD, 13f));
            FontMetrics sm = g2.getFontMetrics();
            String out = override != null ? "" : "/100";
            int total = bm.stringWidth(big) + (out.isEmpty() ? 0 : 4 + sm.stringWidth(out));
            int x = getWidth() - total, base = (getHeight() - bm.getHeight()) / 2 + bm.getAscent();
            g2.setFont(display(36f));
            g2.setColor(gauge.hasScore() ? TEXT : DIM);
            g2.drawString(big, x, base);
            g2.setFont(ui(Font.BOLD, 13f));
            g2.setColor(MUTED);
            g2.drawString(out, x + bm.stringWidth(big) + 4, base);
            g2.dispose();
        }
    }

    /** Small on/off switch. */
    static class Toggle extends JComponent {
        private boolean on;
        private final Runnable onChange;

        Toggle(Runnable onChange) {
            this.onChange = onChange;
            setPreferredSize(new Dimension(36, 22));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override public void mouseClicked(MouseEvent e) {
                    on = !on;
                    repaint();
                    Toggle.this.onChange.run();
                }
            });
        }

        boolean isOn() { return on; }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            g2.setColor(on ? BRAND : RAISED);
            g2.fill(rr(0, 0, getWidth(), getHeight(), getHeight()));
            if (!on) {
                g2.setColor(LINE);
                g2.draw(rr(0.5, 0.5, getWidth() - 1, getHeight() - 1, getHeight()));
            }
            int d = getHeight() - 6;
            g2.setColor(on ? Color.WHITE : MUTED);
            g2.fill(new Ellipse2D.Float(on ? getWidth() - d - 3 : 3, 3, d, d));
            g2.dispose();
        }
    }

    /** Hazard tape that scrolls while a detonation is running. */
    static class Progress extends JComponent {
        private final Timer timer;
        private float offset;

        Progress() {
            setPreferredSize(new Dimension(10, 8));
            timer = new Timer(16, e -> { offset = (offset + 0.7f) % 16f; repaint(); });
        }

        void run(boolean running) {
            if (running) timer.start(); else timer.stop();
            setVisible(running);
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth(), h = getHeight();
            g2.setClip(rr(0, 0, w, h, h));
            g2.setColor(BRAND);
            g2.fillRect(0, 0, w, h);
            g2.setColor(TEXT);
            for (float x = -h * 2 + offset; x < w + h; x += 16f) {
                Path2D p = new Path2D.Float();
                p.moveTo(x, h); p.lineTo(x + 8, h); p.lineTo(x + 8 + h, 0); p.lineTo(x + h, 0); p.closePath();
                g2.fill(p);
            }
            g2.dispose();
        }
    }

    /** Slim scroll bar with a rounded thumb; dark = sitting on the console glass. */
    static void slimScroll(JScrollBar bar, boolean dark) {
        bar.setPreferredSize(new Dimension(10, 10));
        bar.setUnitIncrement(16);
        bar.setOpaque(false);
        final Color thumb = dark ? new Color(216, 236, 229, 70) : LINE;
        final Color thumbHot = dark ? new Color(216, 236, 229, 130) : DIM;
        bar.setUI(new BasicScrollBarUI() {
            @Override protected void configureScrollBarColors() { thumbColor = thumb; trackColor = new Color(0, 0, 0, 0); }
            @Override protected JButton createDecreaseButton(int o) { return zero(); }
            @Override protected JButton createIncreaseButton(int o) { return zero(); }
            private JButton zero() {
                JButton b = new JButton();
                b.setPreferredSize(new Dimension(0, 0));
                return b;
            }
            @Override protected void paintTrack(Graphics g, JComponent c, java.awt.Rectangle r) {
                if (dark) { g.setColor(CONSOLE); g.fillRect(r.x, r.y, r.width, r.height); }
            }
            @Override protected void paintThumb(Graphics g, JComponent c, java.awt.Rectangle r) {
                if (r.isEmpty()) return;
                Graphics2D g2 = smooth(g);
                g2.setColor(isThumbRollover() ? thumbHot : thumb);
                g2.fillRoundRect(r.x + 2, r.y + 2, r.width - 4, r.height - 4, 6, 6);
                g2.dispose();
            }
        });
    }
}
