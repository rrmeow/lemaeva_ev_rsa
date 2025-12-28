import java.awt.*;
import javax.swing.*;

public class RSAGUI extends JFrame {
    
    // компоненты интерфейса
    private JTextField inputFileField;
    private JTextField privateKeyField;
    private JTextField publicKeyField;
    private JTextField signedFileField;
    private JTextArea logArea;
    
    private JButton selectInputBtn;
    private JButton selectPrivateKeyBtn;
    private JButton selectPublicKeyBtn;
    private JButton generateKeysBtn;
    private JButton signBtn;
    private JButton verifyBtn;
    
    private JProgressBar progressBar;
    
    public RSAGUI() {
        setTitle("RSA ЭЦП с SHA-256");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(800, 600);
        setLayout(new BorderLayout());
        
        // создание панелей
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // 1 секция с генерацией ключей
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel("Генерация ключей RSA:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0;
        generateKeysBtn = new JButton("Сгенерировать новую пару ключей");
        generateKeysBtn.addActionListener(e -> generateKeys());
        mainPanel.add(generateKeysBtn, gbc);
        
        // 2 секция с подписью файла
        gbc.gridx = 0; gbc.gridy = 1;
        mainPanel.add(new JLabel("Подпись файла:"), gbc);
        
        // поле выбора файла
        gbc.gridx = 0; gbc.gridy = 2;
        mainPanel.add(new JLabel("Исходный файл:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 2;
        JPanel filePanel = new JPanel(new BorderLayout());
        inputFileField = new JTextField(30);
        filePanel.add(inputFileField, BorderLayout.CENTER);
        selectInputBtn = new JButton("Выбрать...");
        selectInputBtn.addActionListener(e -> chooseFile(inputFileField));
        filePanel.add(selectInputBtn, BorderLayout.EAST);
        mainPanel.add(filePanel, gbc);
        
        // поле выбора приватного ключа
        gbc.gridx = 0; gbc.gridy = 3;
        mainPanel.add(new JLabel("Закрытый ключ:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 3;
        JPanel keyPanel = new JPanel(new BorderLayout());
        privateKeyField = new JTextField(30);
        keyPanel.add(privateKeyField, BorderLayout.CENTER);
        selectPrivateKeyBtn = new JButton("Выбрать...");
        selectPrivateKeyBtn.addActionListener(e -> chooseFile(privateKeyField));
        keyPanel.add(selectPrivateKeyBtn, BorderLayout.EAST);
        mainPanel.add(keyPanel, gbc);
        
        gbc.gridx = 1; gbc.gridy = 4;
        signBtn = new JButton("Подписать файл");
        signBtn.addActionListener(e -> signFile());
        mainPanel.add(signBtn, gbc);
        
        // 3 секция с проверкой подписи
        gbc.gridx = 0; gbc.gridy = 5;
        mainPanel.add(new JLabel("Проверка подписи:"), gbc);
        
        gbc.gridx = 0; gbc.gridy = 6;
        mainPanel.add(new JLabel("Подписанный файл:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 6;
        JPanel signedPanel = new JPanel(new BorderLayout());
        signedFileField = new JTextField(30);
        signedPanel.add(signedFileField, BorderLayout.CENTER);
        JButton selectSignedBtn = new JButton("Выбрать...");
        selectSignedBtn.addActionListener(e -> chooseFile(signedFileField));
        signedPanel.add(selectSignedBtn, BorderLayout.EAST);
        mainPanel.add(signedPanel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 7;
        mainPanel.add(new JLabel("Открытый ключ:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 7;
        JPanel publicKeyPanel = new JPanel(new BorderLayout());
        publicKeyField = new JTextField(30);
        publicKeyPanel.add(publicKeyField, BorderLayout.CENTER);
        selectPublicKeyBtn = new JButton("Выбрать...");
        selectPublicKeyBtn.addActionListener(e -> chooseFile(publicKeyField));
        publicKeyPanel.add(selectPublicKeyBtn, BorderLayout.EAST);
        mainPanel.add(publicKeyPanel, gbc);
        
        gbc.gridx = 1; gbc.gridy = 8;
        verifyBtn = new JButton("Проверить подпись");
        verifyBtn.addActionListener(e -> verifySignature());
        mainPanel.add(verifyBtn, gbc);
        
        // лог-панель
        logArea = new JTextArea(10, 60);
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        
        // прогресс-бар
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        
        // сборка интерфейса
        add(mainPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(progressBar, BorderLayout.SOUTH);
        
        setLocationRelativeTo(null); // центрируем окно
    }
    
    private void chooseFile(JTextField field) {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            field.setText(fileChooser.getSelectedFile().getAbsolutePath());
        }
    }
    
    private void generateKeys() {
        log("Начата генерация ключей...");
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        
        // запуск в отдельном потоке (чтоб не висло)
        SwingWorker<Void, String> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    // вызов метода генерации ключей
                    RSA.generateKeys(2048, "private.key", "public.key");
                    publish("Ключи успешно сгенерированы!");
                    publish("Закрытый ключ сохранен: private.key");
                    publish("Открытый ключ сохранен: public.key");
                } catch (Exception e) {
                    publish("Ошибка при генерации ключей: " + e.getMessage());
                }
                return null;
            }
            
            @Override
            protected void process(java.util.List<String> chunks) {
                for (String message : chunks) {
                    log(message);
                }
            }
            
            @Override
            protected void done() {
                progressBar.setVisible(false);
                progressBar.setIndeterminate(false);
            }
        };
        
        worker.execute();
    }
    
    private void signFile() {
        String inputFile = inputFileField.getText();
        String privateKeyFile = privateKeyField.getText();
        
        if (inputFile.isEmpty() || privateKeyFile.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Выберите файл и закрытый ключ!", 
                "Ошибка", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        log("Начато подписание файла: " + inputFile);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        
        SwingWorker<Void, String> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    // вызов метода подписания
                    String signatureFile = RSA.signFile(inputFile, privateKeyFile);
                    publish("Файл успешно подписан!");
                    publish("Подпись сохранена в: " + signatureFile);
                } catch (Exception e) {
                    publish("Ошибка при подписании: " + e.getMessage());
                }
                return null;
            }
            
            @Override
            protected void process(java.util.List<String> chunks) {
                for (String message : chunks) {
                    log(message);
                }
            }
            
            @Override
            protected void done() {
                progressBar.setVisible(false);
                progressBar.setIndeterminate(false);
            }
        };
        
        worker.execute();
    }
    
    private void verifySignature() {
        String signedFile = signedFileField.getText();
        String publicKeyFile = publicKeyField.getText();
        
        if (signedFile.isEmpty() || publicKeyFile.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Выберите подписанный файл и открытый ключ!", 
                "Ошибка", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        log("Начата проверка подписи для файла: " + signedFile);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        
        SwingWorker<Boolean, String> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                try {
                    // вызов метода проверки
                    boolean isValid = RSA.verifySignature(signedFile, publicKeyFile);
                    if (isValid) {
                        publish("Подпись верна. Файл не изменен.");
                    } else {
                        publish("Подпись неверна. Файл был изменен или подпись некорректна.");
                    }
                    return isValid;
                } catch (Exception e) {
                    publish("Ошибка при проверке: " + e.getMessage());
                    return false;
                }
            }
            
            @Override
            protected void process(java.util.List<String> chunks) {
                for (String message : chunks) {
                    log(message);
                }
            }
            
            @Override
            protected void done() {
                progressBar.setVisible(false);
                progressBar.setIndeterminate(false);
            }
        };
        
        worker.execute();
    }
    
    private void log(String message) {
        logArea.append("[" + java.time.LocalTime.now().format(
            java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")) + "] " + message + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength()); // автопрокрутка
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            RSAGUI gui = new RSAGUI();
            gui.setVisible(true);
        });
    }
}