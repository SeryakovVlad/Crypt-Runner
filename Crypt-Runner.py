import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget,
    QTextEdit, QLabel, QTreeWidgetItem, QListWidget, QListWidgetItem, QGridLayout,
    QPushButton, QFrame, QInputDialog, QDialog, QDialogButtonBox, QLineEdit, QFileDialog
)
from PyQt5.QtCore import Qt, QMimeData, QPoint
from PyQt5.QtGui import QDrag, QPalette, QColor, QIcon
import base64
import py3base92
import codecs

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.oldPos = self.pos()
        self.initUI()
        

    def initUI(self):
        # Убираем стандартную заголовочную панель
        self.setWindowFlags(Qt.FramelessWindowHint)
        
        # Основной макет
        mainLayout = QVBoxLayout()
        mainLayout.setContentsMargins(0, 0, 0, 0)

        # Кастомная заголовочная панель
        titleBar = QFrame()
        titleBar.setStyleSheet("background-color: #353535; color: white;")
        titleBar.setFixedHeight(40)
        titleBarLayout = QHBoxLayout()
        titleBarLayout.setContentsMargins(0, 0, 0, 0)
        
        # Иконка приложения
        self.setWindowIcon(QIcon('source/key.png'))
        iconLabel = QLabel()
        iconLabel.setPixmap(QIcon('source/key.png').pixmap(20, 20))
        iconLabel.setStyleSheet("border: none; margin-left: 10px;")  # Убираем рамку у иконки
        
        # Заголовок
        titleLabel = QLabel("Crypt-Runner")
        titleLabel.setAlignment(Qt.AlignCenter)
        titleLabel.setStyleSheet("margin-left: 5px; color: #D3AFFF;")

        # Кнопки управления
        minButton = QPushButton('—')
        minButton.setFixedSize(40, 40)
        minButton.setStyleSheet("color: #D3AFFF; border: none;")
        minButton.clicked.connect(self.showMinimized)

        maxButton = QPushButton('☐')
        maxButton.setFixedSize(40, 40)
        maxButton.setStyleSheet("color: #D3AFFF; border: none;")
        maxButton.clicked.connect(self.toggleMaximized)

        closeButton = QPushButton('Х')
        closeButton.setFixedSize(40, 40)
        closeButton.setStyleSheet("color: #D3AFFF; border: none;")
        closeButton.clicked.connect(self.close)
        
        # Кнопка Download
        downloadButton = QPushButton('Download')
        downloadButton.clicked.connect(self.downloadFile)

        titleBarLayout.addWidget(iconLabel)
        titleBarLayout.addWidget(titleLabel)
        titleBarLayout.addStretch()
        titleBarLayout.addWidget(minButton)
        titleBarLayout.addWidget(maxButton)
        titleBarLayout.addWidget(closeButton)
        titleBar.setLayout(titleBarLayout)

        contentLayout = QHBoxLayout()

        # Дерево кодировок
        self.encodingsTree = QTreeWidget()
        self.encodingsTree.setHeaderHidden(True)
        self.encodingsTree.setDragEnabled(True)
        self.encodingsTree.installEventFilter(self)

        # Создание элементов дерева
        text_encoding_item = QTreeWidgetItem(self.encodingsTree)
        text_encoding_item.setText(0, 'Text encoding')
        text_encoding_item.setFlags(text_encoding_item.flags() & ~Qt.ItemIsDragEnabled)  # Disable drag for this item

        data_format_item = QTreeWidgetItem(self.encodingsTree)
        data_format_item.setText(0, 'Data format')
        data_format_item.setFlags(data_format_item.flags() & ~Qt.ItemIsDragEnabled)  # Disable drag for this item

        numeric_encoding_item = QTreeWidgetItem(self.encodingsTree)
        numeric_encoding_item.setText(0, 'Numeric Encoding')
        numeric_encoding_item.setFlags(numeric_encoding_item.flags() & ~Qt.ItemIsDragEnabled)  # Disable drag for this item

        base64_encode_item = QTreeWidgetItem(numeric_encoding_item)
        base64_encode_item.setText(0, 'Base64 Encode')
        base64_decode_item = QTreeWidgetItem(numeric_encoding_item)
        base64_decode_item.setText(0, 'Base64 Decode')

        base45_encode_item = QTreeWidgetItem(numeric_encoding_item)
        base45_encode_item.setText(0, 'Base45 Encode')
        base45_decode_item = QTreeWidgetItem(numeric_encoding_item)
        base45_decode_item.setText(0, 'Base45 Decode')
        
        base58_encode_item = QTreeWidgetItem(numeric_encoding_item)
        base58_encode_item.setText(0, 'Base58 Encode')
        base58_decode_item = QTreeWidgetItem(numeric_encoding_item)
        base58_decode_item.setText(0, 'Base58 Decode')
        
        base62_encode_item = QTreeWidgetItem(numeric_encoding_item)
        base62_encode_item.setText(0, 'Base62 Encode')
        base62_decode_item = QTreeWidgetItem(numeric_encoding_item)
        base62_decode_item.setText(0, 'Base62 Decode')
        
        base85_encode_item = QTreeWidgetItem(numeric_encoding_item)
        base85_encode_item.setText(0, 'Base85 Encode')
        base85_decode_item = QTreeWidgetItem(numeric_encoding_item)
        base85_decode_item.setText(0, 'Base85 Decode')
        
        base92_encode_item = QTreeWidgetItem(numeric_encoding_item)
        base92_encode_item.setText(0, 'Base92 Encode')
        base92_decode_item = QTreeWidgetItem(numeric_encoding_item)
        base92_decode_item.setText(0, 'Base92 Decode')

        base_n_encode_item = QTreeWidgetItem(numeric_encoding_item)
        base_n_encode_item.setText(0, 'Base-N Encode')
        base_n_decode_item = QTreeWidgetItem(numeric_encoding_item)
        base_n_decode_item.setText(0, 'Base-N Decode')

        hexdump_encode_item = QTreeWidgetItem(data_format_item)
        hexdump_encode_item.setText(0, 'Hexdump Encode')
        hexdump_decode_item = QTreeWidgetItem(data_format_item)
        hexdump_decode_item.setText(0, 'Hexdump Decode')

        decimal_encode_item = QTreeWidgetItem(numeric_encoding_item)
        decimal_encode_item.setText(0, 'Decimal Encode')
        decimal_decode_item = QTreeWidgetItem(numeric_encoding_item)
        decimal_decode_item.setText(0, 'Decimal Decode')

        binary_encode_item = QTreeWidgetItem(numeric_encoding_item)
        binary_encode_item.setText(0, 'Binary Encode')
        binary_decode_item = QTreeWidgetItem(numeric_encoding_item)
        binary_decode_item.setText(0, 'Binary Decode')

        octal_encode_item = QTreeWidgetItem(numeric_encoding_item)
        octal_encode_item.setText(0, 'Octal Encode')
        octal_decode_item = QTreeWidgetItem(numeric_encoding_item)
        octal_decode_item.setText(0, 'Octal Decode')

        hex_encode_item = QTreeWidgetItem(numeric_encoding_item)
        hex_encode_item.setText(0, 'Hexadecimal Encode')
        hex_decode_item = QTreeWidgetItem(numeric_encoding_item)
        hex_decode_item.setText(0, 'Hexadecimal Decode')

        url_encode_item = QTreeWidgetItem(data_format_item)
        url_encode_item.setText(0, 'URL Encode')
        url_decode_item = QTreeWidgetItem(data_format_item)
        url_decode_item.setText(0, 'URL Decode')

        utf16_le_encode_item = QTreeWidgetItem(text_encoding_item)
        utf16_le_encode_item.setText(0, 'UTF-16 LE Encode')
        utf16_le_decode_item = QTreeWidgetItem(text_encoding_item)
        utf16_le_decode_item.setText(0, 'UTF-16 LE Decode')
        utf16_be_encode_item = QTreeWidgetItem(text_encoding_item)
        utf16_be_encode_item.setText(0, 'UTF-16 BE Encode')
        utf16_be_decode_item = QTreeWidgetItem(text_encoding_item)
        utf16_be_decode_item.setText(0, 'UTF-16 BE Decode')
        utf32_le_encode_item = QTreeWidgetItem(text_encoding_item)
        utf32_le_encode_item.setText(0, 'UTF-32 LE Encode')
        utf32_le_decode_item = QTreeWidgetItem(text_encoding_item)
        utf32_le_decode_item.setText(0, 'UTF-32 LE Decode')
        utf32_be_encode_item = QTreeWidgetItem(text_encoding_item)
        utf32_be_encode_item.setText(0, 'UTF-32 BE Encode')
        utf32_be_decode_item = QTreeWidgetItem(text_encoding_item)
        utf32_be_decode_item.setText(0, 'UTF-32 BE Decode')

        self.dropArea = QListWidget()
        self.dropArea.setAcceptDrops(True)
        self.dropArea.installEventFilter(self)

        self.inputField = QTextEdit()
        self.resultField = QTextEdit()
        self.resultField.setReadOnly(True)

        self.inputLabel = QLabel('Input')
        self.inputLabel.setAlignment(Qt.AlignCenter)
        self.resultLabel = QLabel('Result')
        self.resultLabel.setAlignment(Qt.AlignCenter)

        inputLayout = QHBoxLayout()
        inputLayout.addWidget(self.inputLabel)  # Используйте self.inputLabel здесь
        inputLayout.addWidget(downloadButton)
        inputLayout.addStretch()

        encodingLayout = QVBoxLayout()
        encodingLabel = QLabel('Encodings')
        encodingLabel.setAlignment(Qt.AlignCenter)
        encodingLayout.addWidget(encodingLabel)
        encodingLayout.addWidget(self.encodingsTree)
        
        processLayout = QVBoxLayout()
        processLabel = QLabel('Drop Area')
        processLabel.setAlignment(Qt.AlignCenter)
        processLayout.addWidget(processLabel)
        processLayout.addWidget(self.dropArea)
        
        ioLayout = QGridLayout()
        ioLayout.addLayout(inputLayout, 0, 0)  # Добавляем inputLayout здесь
        ioLayout.addWidget(self.inputField, 1, 0)
        ioLayout.addWidget(self.resultLabel, 2, 0)
        ioLayout.addWidget(self.resultField, 3, 0)

        contentLayout.addLayout(encodingLayout)
        contentLayout.addLayout(processLayout)
        contentLayout.addLayout(ioLayout)

        mainLayout.addWidget(titleBar)
        mainLayout.addLayout(contentLayout)
        self.setLayout(mainLayout)
        
        self.setWindowTitle('Crypt-Runner')
        self.setGeometry(100, 100, 800, 600)
        
        # Связывание событий
        self.inputField.textChanged.connect(self.processText)
        self.encodingsTree.itemPressed.connect(self.startDrag)
        self.dropArea.itemPressed.connect(self.dropArea_startDrag)
        self.dropArea.setDropIndicatorShown(True)

        # Применение темной темы
        self.applyDarkTheme()


    def applyDarkTheme(self):
        dark_palette = QPalette()

        # Основные цвета
        dark_color = QColor(30, 30, 30)  # Очень темный серый, почти черный
        medium_color = QColor(45, 45, 45)  # Темно-серый
        light_color = QColor(60, 60, 60)  # Серый
        text_color = QColor(211, 175, 255)  # Светло-фиолетовый для текста
        highlight_color = QColor(148, 0, 211)  # Яркий фиолетовый (Dark Violet)

        # Настройка палитры
        dark_palette.setColor(QPalette.Window, dark_color)
        dark_palette.setColor(QPalette.WindowText, text_color)
        dark_palette.setColor(QPalette.Base, medium_color)
        dark_palette.setColor(QPalette.AlternateBase, light_color)
        dark_palette.setColor(QPalette.ToolTipBase, highlight_color)
        dark_palette.setColor(QPalette.ToolTipText, text_color)
        dark_palette.setColor(QPalette.Text, text_color)
        dark_palette.setColor(QPalette.Button, medium_color)
        dark_palette.setColor(QPalette.ButtonText, text_color)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, highlight_color)
        dark_palette.setColor(QPalette.Highlight, highlight_color)
        dark_palette.setColor(QPalette.HighlightedText, text_color)

        QApplication.setPalette(dark_palette)

        self.setStyleSheet("""
            QWidget {
                background-color: #1E1E1E;
                color: #D3AFFF;
                border-radius: 10px;
            }
            QTreeWidget, QListWidget, QTextEdit {
                background-color: #2D2D2D;
                border-radius: 5px;
            }
            QTreeWidget::item, QListWidget::item {
                border-radius: 2px;
                padding: 2px;
            }
            QTreeWidget::item:selected, QListWidget::item:selected {
                background-color: #9400D3;
                color: #FFFFFF;
            }
            QTextEdit {
                padding: 5px;
            }
            QPushButton {
                background-color: #3A3A3A;
                color: #D3AFFF;
                border: none;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #4A4A4A;
            }
            QPushButton:pressed {
                background-color: #9400D3;
            }
            QLabel {
                background-color: transparent;
                color: #D3AFFF;
            }
            #titleBar {
                background-color: #2D2D2D;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
            }
            #titleBar QLabel {
                color: #FFFFFF;
            }
            #titleBar QPushButton {
                background-color: transparent;
                border-radius: 0px;
            }
            #titleBar QPushButton:hover {
                background-color: #4A4A4A;
            }
        """)

    def processText(self):
        input_text = self.inputField.toPlainText()
        operations = []
        for index in range(self.dropArea.count()):
            item = self.dropArea.item(index)
            operations.append((item.text(), item.data(Qt.UserRole)))

        result_text = input_text
        for operation, base in operations:
            if 'Base-N Encode' in operation:
                if base is not None:
                    result_text = self.base_n_encode(result_text, int(base))
                else:
                    result_text = "Error: Base value is not set for Base-N Encode"
            elif 'Base-N Decode' in operation:
                if base is not None:
                    result_text = self.base_n_decode(result_text, int(base))
                else:
                    result_text = "Error: Base value is not set for Base-N Decode"
            elif operation == 'Base64 Encode':
                result_text = self.base64_encode(result_text)
            elif operation == 'Base64 Decode':
                result_text = self.base64_decode(result_text)
            elif operation == 'Base64 Encode':
                result_text = self.base64_encode(result_text)
            elif operation == 'Base64 Decode':
                result_text = self.base64_decode(result_text)
            elif operation == 'Base45 Encode':
                result_text = self.base45_encode(result_text)
            elif operation == 'Base45 Decode':
                result_text = self.base45_decode(result_text)
            elif operation == 'Base58 Encode':
                result_text = self.base58_encode(result_text)
            elif operation == 'Base58 Decode':
                result_text = self.base58_decode(result_text)
            elif operation == 'Base62 Encode':
                result_text = self.base62_encode(result_text)
            elif operation == 'Base62 Decode':
                result_text = self.base62_decode(result_text)
            elif operation == 'Base85 Encode':
                result_text = self.base85_encode(result_text)
            elif operation == 'Base85 Decode':
                result_text = self.base85_decode(result_text)
            elif operation == 'Base92 Encode':
                result_text = self.base92_encode(result_text)
            elif operation == 'Base92 Decode':
                result_text = self.base92_decode(result_text)
            elif operation == 'URL Encode':
                result_text = self.url_encode(result_text)
            elif operation == 'URL Decode':
                result_text = self.url_decode(result_text)
            elif operation == 'Hexdump Encode':
                result_text = self.hexdump_encode(result_text)
            elif operation == 'Hexdump Decode':
                result_text = self.hexdump_decode(result_text)
            elif operation == 'UTF-16 LE Encode':
                result_text = self.utf16_le_encode(result_text)
            elif operation == 'UTF-16 LE Decode':
                result_text = self.utf16_le_decode(result_text)
            elif operation == 'UTF-16 BE Encode':
                result_text = self.utf16_be_encode(result_text)
            elif operation == 'UTF-16 BE Decode':
                result_text = self.utf16_be_decode(result_text)
            elif operation == 'UTF-32 LE Encode':
                result_text = self.utf32_le_encode(result_text)
            elif operation == 'UTF-32 LE Decode':
                result_text = self.utf32_le_decode(result_text)
            elif operation == 'UTF-32 BE Encode':
                result_text = self.utf32_be_encode(result_text)
            elif operation == 'UTF-32 BE Decode':
                result_text = self.utf32_be_decode(result_text)
            elif operation == 'Binary Encode':
                result_text = self.binary_encode(result_text)
            elif operation == 'Binary Decode':
                result_text = self.binary_decode(result_text)
            elif operation == 'Octal Encode':
                result_text = self.octal_encode(result_text)
            elif operation == 'Octal Decode':
                result_text = self.octal_decode(result_text)
            elif operation == 'Hexadecimal Encode':
                result_text = self.hexadecimal_encode(result_text)
            elif operation == 'Hexadecimal Decode':
                result_text = self.hexadecimal_decode(result_text)
            elif operation == 'Decimal Encode':
                result_text = self.decimal_encode(result_text)
            elif operation == 'Decimal Decode':
                result_text = self.decimal_decode(result_text)

        if isinstance(result_text, bytes):
            try:
                result_text = result_text.decode('utf-8')  # Декодируем байты в строку UTF-8
            except UnicodeDecodeError:
                result_text = ""

        self.resultField.setText(result_text)
    
    def base64_encode(self, text):
        import base64
        return base64.b64encode(text.encode()).decode()

    def base64_decode(self, text):
        import base64
        return base64.b64decode(text.encode()).decode()

    def base45_encode(self, text):
        try:
            import base45
            return base45.b45encode(text.encode('utf-8')).decode('utf-8')
        except ImportError:
            return "Base45 library not installed"

    def base45_decode(self, text):
        try:
            import base45
            return base45.b45decode(text.encode('utf-8')).decode('utf-8')
        except ImportError:
            return "Base45 library not installed"
        except Exception as e:
            return str(e)

    def base58_encode(self, text):
        try:
            import base58
            return base58.b58encode(text.encode('utf-8')).decode('utf-8')
        except ImportError:
            return "Base58 library not installed"

    def base58_decode(self, text):
        try:
            import base58
            return base58.b58decode(text.encode('utf-8')).decode('utf-8')
        except ImportError:
            return "Base58 library not installed"
        except Exception as e:
            return str(e)

    def base62_encode(self, text):
        # Base62 encoding without external library
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        base = len(alphabet)
        num = int.from_bytes(text.encode('utf-8'), 'big')
        if num == 0:
            return alphabet[0]
        encoded = []
        while num:
            num, rem = divmod(num, base)
            encoded.append(alphabet[rem])
        return ''.join(reversed(encoded))

    def base62_decode(self, text):
        # Base62 decoding without external library
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        base = len(alphabet)
        num = 0
        for char in text:
            num = num * base + alphabet.index(char)
        decoded_bytes = num.to_bytes((num.bit_length() + 7) // 8, 'big')
        try:
            return decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return decoded_bytes

    def base85_encode(self, text):
        return base64.b85encode(text.encode('utf-8')).decode('utf-8')

    def base85_decode(self, text):
        try:
            return base64.b85decode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return str(e)

    def base92_encode(self, text):
        encoded_string = py3base92.b92encode(text.encode())
        return encoded_string

    def base92_decode(self, text):
        try:
            decoded_bytes = py3base92.b92decode(text)
            return decoded_bytes.decode()
        except py3base92.Base92Error as e:
            return f"Error decoding Base92: {str(e)}"

    def url_encode(self, text):
        from urllib.parse import quote
        return quote(text)
        
    def url_decode(self, text):
        from urllib.parse import unquote
        return unquote(text)
    
    def hex_encode(self, text):
        return text.encode().hex()

    def hex_decode(self, text):
        try:
            decoded_text = bytes.fromhex(text).decode('utf-8')
            return decoded_text
        except ValueError:
            return "Invalid Hexadecimal Input"
        
    def hexdump_encode(self, text):
        import binascii
        return binascii.hexlify(text.encode()).decode()

    def hexdump_decode(self, text):
        import binascii
        try:
            decoded_text = binascii.unhexlify(text.encode()).decode('utf-8')
            return decoded_text
        except binascii.Error:
            return "Invalid Hexdump Input"
    
    def decimal_encode(self, text):
        decimal_encoded = []
        for char in text:
            decimal_encoded.append(str(ord(char)))
        return ' '.join(decimal_encoded)

    def decimal_decode(self, text):
        try:
            decimal_decoded = []
            for num_str in text.split():
                decimal_decoded.append(chr(int(num_str)))
            return ''.join(decimal_decoded)
        except ValueError:
            return "Invalid Decimal Input"

    def binary_encode(self, text):
        return ' '.join(format(ord(char), '08b') for char in text)

    def binary_decode(self, text):
        try:
            decoded_text = ''.join(chr(int(binary, 2)) for binary in text.split())
            return decoded_text
        except ValueError:
            return "Invalid Binary Input"
    
    def octal_encode(self, text):
        octal_encoded = []
        for char in text:
            octal_encoded.append(format(ord(char), '03o'))  # 3-digit octal representation
        return ' '.join(octal_encoded)

    def octal_decode(self, text):
        try:
            octal_decoded = []
            for oct_str in text.split():
                octal_decoded.append(chr(int(oct_str, 8)))
            return ''.join(octal_decoded)
        except ValueError:
            return "Invalid Octal Input"

    def hexadecimal_encode(self, text):
        hexadecimal_encoded = []
        for char in text:
            hexadecimal_encoded.append(format(ord(char), '02X'))  # 2-digit hexadecimal representation
        return ' '.join(hexadecimal_encoded)

    def hexadecimal_decode(self, text):
        try:
            hexadecimal_decoded = []
            for hex_str in text.split():
                hexadecimal_decoded.append(chr(int(hex_str, 16)))
            return ''.join(hexadecimal_decoded)
        except ValueError:
            return "Invalid Hexadecimal Input"
        
    def utf16_le_encode(self, text):
        try:
            encoded_text = text.encode('utf-16le')
            return encoded_text
        except Exception as e:
            return f"Error encoding: {str(e)}"

    def utf16_le_decode(self, encoded_text):
        try:
            decoded_text = encoded_text.decode('utf-16le')
            return decoded_text
        except Exception as e:
            return f"Error decoding: {str(e)}"

    def utf16_be_encode(self, text):
        try:
            encoded_text = text.encode('utf-16be')
            return encoded_text
        except Exception as e:
            return f"Error encoding: {str(e)}"

    def utf16_be_decode(self, encoded_text):
        try:
            decoded_text = encoded_text.decode('utf-16be')
            return decoded_text
        except Exception as e:
            return f"Error decoding: {str(e)}"

    def utf32_le_encode(self, text):
        try:
            encoded_text = text.encode('utf-32le')
            return encoded_text
        except Exception as e:
            return f"Error encoding: {str(e)}"

    def utf32_le_decode(self, encoded_text):
        try:
            decoded_text = encoded_text.decode('utf-32le')
            return decoded_text
        except Exception as e:
            return f"Error decoding: {str(e)}"

    def utf32_be_encode(self, text):
        try:
            encoded_text = text.encode('utf-32be')
            return encoded_text
        except Exception as e:
            return f"Error encoding: {str(e)}"

    def utf32_be_decode(self, encoded_text):
        try:
            decoded_text = encoded_text.decode('utf-32be')
            return decoded_text
        except Exception as e:
            return f"Error decoding: {str(e)}"

    def base_n_encode(self, text, base):
        if base is None:
            return "Error: Base value is not set"
        try:
            result = []
            for char in text:
                num = ord(char)
                encoded = ""
                while num > 0:
                    num, remainder = divmod(num, base)
                    encoded = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[remainder] + encoded
                result.append(encoded.zfill(2))
            return ' '.join(result)
        except Exception as e:
            return f"Error in Base-{base} Encoding: {str(e)}"

    def base_n_decode(self, text, base):
        if base is None:
            return "Error: Base value is not set"
        try:
            result = []
            for encoded in text.split():
                num = 0
                for digit in encoded:
                    num = num * base + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".index(digit.upper())
                result.append(chr(num))
            return ''.join(result)
        except Exception as e:
            return f"Error in Base-{base} Decoding: {str(e)}"

    def downloadFile(self):
        # Открытие диалогового окна выбора файла
        fileDialog = QFileDialog(self)
        fileDialog.setFileMode(QFileDialog.ExistingFile)
        if fileDialog.exec_():
            filenames = fileDialog.selectedFiles()
            if filenames:
                filename = filenames[0]
                try:
                    with codecs.open(filename, 'r', encoding='utf-8') as file:  # Указываем кодировку UTF-8
                        content = file.read()
                        self.inputField.setPlainText(content)
                        self.processText()  # Перерасчет результатов после загрузки файла
                except Exception as e:
                    print(f"Error loading file: {e}")

    def eventFilter(self, obj, event):
        if obj == self.dropArea:
            if event.type() == event.DragEnter:
                mimeData = event.mimeData()
                if mimeData.hasFormat("text/plain"):
                    event.acceptProposedAction()
                    return True
                else:
                    return super().eventFilter(obj, event)

            elif event.type() == event.Drop:
                mimeData = event.mimeData()
                if mimeData.hasFormat("text/plain"):
                    item_text = mimeData.text()
                    if not self.isItemInDropArea(item_text):
                        item = QListWidgetItem(item_text)
                        if mimeData.hasFormat("application/x-base-n"):
                            base = int(mimeData.data("application/x-base-n").data().decode())
                            item.setData(Qt.UserRole, base)
                        self.dropArea.addItem(item)
                        self.processText()
                        event.acceptProposedAction()
                        return True
                return super().eventFilter(obj, event)

            elif event.type() == event.KeyPress:
                if event.key() in (Qt.Key_Backspace, Qt.Key_Delete):
                    selected_items = self.dropArea.selectedItems()
                    if selected_items:
                        selected_item = selected_items[0]
                        self.dropArea.takeItem(self.dropArea.row(selected_item))
                        self.processText()
                    return True

        elif obj == self.encodingsTree:
            if event.type() == event.MouseMove:
                if event.buttons() & Qt.LeftButton:
                    item = self.encodingsTree.itemAt(event.pos())
                    if item and item.text(0):  # Ensure there is an item under the mouse
                        drag = QDrag(self)
                        mimeData = QMimeData()
                        mimeData.setText(item.text(0))
                        drag.setMimeData(mimeData)
                        drag.exec_(Qt.MoveAction)
                    return True

        return super().eventFilter(obj, event)

    def isItemInDropArea(self, item_text):
        for index in range(self.dropArea.count()):
            if self.dropArea.item(index).text() == item_text:
                return True
        return False

    def startDrag(self, item, column):
        if isinstance(item, QTreeWidgetItem):
            if item.childCount() == 0 and item.parent():  # Only drag leaf nodes (actual encodings) and not root items
                drag = QDrag(self.encodingsTree)
                mimeData = QMimeData()
                mimeData.setText(item.text(0))
                drag.setMimeData(mimeData)
                drag.exec_(Qt.MoveAction)

    def dropArea_startDrag(self, item):
        if 'Base-N' in item.text():
            current_base = item.data(Qt.UserRole)
            if current_base is None:
                # Если base еще не установлен, запрашиваем его у пользователя
                base, ok = QInputDialog.getInt(self, "Enter Base", "Base Value:", 10, 2, 36)
                if ok:
                    new_text = f"{item.text()} (Base-{base})"
                    item.setText(new_text)
                    item.setData(Qt.UserRole, int(base))
                    self.processText()
            else:
                # Если base уже установлен, начинаем перетаскивание
                drag = QDrag(self.dropArea)
                mimeData = QMimeData()
                mimeData.setText(item.text())
                mimeData.setData("application/x-base-n", str(current_base).encode())
                drag.setMimeData(mimeData)
                drag.exec_(Qt.MoveAction)
        else:
            # Для не Base-N элементов оставляем прежнюю логику
            drag = QDrag(self.dropArea)
            mimeData = QMimeData()
            mimeData.setText(item.text())
            drag.setMimeData(mimeData)
            drag.exec_(Qt.MoveAction)
        
        self.processText()

    def mousePressEvent(self, event):
        if event.source() == self.dropArea:
            item = self.dropArea.itemAt(event.pos())
            if item:
                self.dropArea.takeItem(self.dropArea.row(item))
                self.processText()
            return True

        if event.button() == Qt.LeftButton:
            self.oldPos = event.globalPos()
        event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton:
            delta = QPoint(event.globalPos() - self.oldPos)
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.oldPos = event.globalPos()
        event.accept()

    def toggleMaximized(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())