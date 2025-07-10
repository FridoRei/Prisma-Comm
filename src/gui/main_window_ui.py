from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QSizePolicy, QSpacerItem, QStackedWidget, QLineEdit, QTextEdit
)
from PySide6.QtGui import QIcon, QFont
from PySide6.QtCore import QSize, Qt


class MainWindowUI:
    def setup_ui(self, parent):
        parent.setWindowTitle("Conexão Segura")
        parent.resize(800, 400)

        parent.central_widget = QWidget()
        parent.setCentralWidget(parent.central_widget)

        main_layout = QHBoxLayout(parent.central_widget)

        sidebar_layout = QVBoxLayout()
        sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        sidebar_button_style = """
            QPushButton {
                background-color: #2e2e2f; /* Cor de fundo para os botões */
                border: 2px solid #555; /* Borda */
                border-radius: 20px; /* Metade do tamanho fixo (40/2) para ser circular */
                color: white;
            }
            QPushButton:hover {
                background-color: #3e3e3f;
            }
            QPushButton:pressed {
                background-color: #1e1e1f;
            }
        """

        parent.btn_home = QPushButton("")
        parent.btn_home.setIcon(QIcon.fromTheme("go-home"))
        parent.btn_home.setIconSize(QSize(20, 20))
        parent.btn_home.setFixedSize(40, 40)
        parent.btn_home.setCursor(Qt.CursorShape.PointingHandCursor)
        parent.btn_home.setToolTip("Início")
        parent.btn_home.setStyleSheet(sidebar_button_style) 
        sidebar_layout.addWidget(parent.btn_home)

        parent.btn_settings = QPushButton("")
        parent.btn_settings.setIcon(QIcon.fromTheme("preferences-system"))
        parent.btn_settings.setIconSize(QSize(20, 20))
        parent.btn_settings.setFixedSize(40, 40)
        parent.btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        parent.btn_settings.setToolTip("Configurações")
        parent.btn_settings.setStyleSheet(sidebar_button_style) 
        sidebar_layout.addWidget(parent.btn_settings)

        parent.btn_chat = QPushButton("")
        parent.btn_chat.setIcon(QIcon.fromTheme("mail-message-new")) 
        parent.btn_chat.setIconSize(QSize(20, 20))
        parent.btn_chat.setFixedSize(40, 40)
        parent.btn_chat.setCursor(Qt.CursorShape.PointingHandCursor)
        parent.btn_chat.setToolTip("Chat")
        parent.btn_chat.setStyleSheet(sidebar_button_style) 
        sidebar_layout.addWidget(parent.btn_chat)

        parent.btn_logs = QPushButton("")
        parent.btn_logs.setIcon(QIcon.fromTheme("user-available")) 
        parent.btn_logs.setIconSize(QSize(20, 20))
        parent.btn_logs.setFixedSize(40, 40)
        parent.btn_logs.setCursor(Qt.CursorShape.PointingHandCursor)
        parent.btn_logs.setToolTip("Logs")
        parent.btn_logs.setStyleSheet(sidebar_button_style) 
        sidebar_layout.addWidget(parent.btn_logs)

        sidebar_layout.addStretch()

        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar_layout)
        sidebar_widget.setFixedWidth(60)
        sidebar_widget.setStyleSheet("""
            background-color: #1e1e1f;
            border-radius: 15px;
            padding: 10px;
        """)

        parent.stacked_widget = QStackedWidget()
        main_layout.addWidget(parent.stacked_widget)

        parent.home_page = QWidget()
        home_layout = QVBoxLayout(parent.home_page)
        home_layout.addSpacerItem(QSpacerItem(20, 50, QSizePolicy.Minimum, QSizePolicy.Expanding))

        parent.label_home = QLabel("Selecione o modo de conexão:")
        parent.label_home.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(18)
        parent.label_home.setFont(font)
        parent.label_home.setStyleSheet("color: white;") 
        home_layout.addWidget(parent.label_home)

        buttons_container = QWidget()
        buttons_container_layout = QHBoxLayout(buttons_container)
        buttons_container.setStyleSheet("""
            background-color: #3e3e3f; /* Cor de fundo do retângulo */
            border: 1px solid #555; /* Borda */
            border-radius: 10px; /* Bordas arredondadas */
            padding: 20px; /* Espaçamento interno */
        """)

        host_join_button_style = """
            QPushButton {
                background-color: #555;
                border: none;
                border-radius: 8px;
                color: white;
                font-size: 16px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """

        parent.btn_host = QPushButton("Hospedar Rede")
        parent.btn_host.setIcon(QIcon.fromTheme("network-wireless"))
        parent.btn_host.setIconSize(QSize(32, 32))
        parent.btn_host.setFixedSize(200, 80)
        parent.btn_host.setCursor(Qt.CursorShape.PointingHandCursor)
        parent.btn_host.setStyleSheet(host_join_button_style) 

        parent.btn_join = QPushButton("Juntar-se à Rede")
        parent.btn_join.setIcon(QIcon.fromTheme("contact-new"))
        parent.btn_join.setIconSize(QSize(32, 32))
        parent.btn_join.setFixedSize(200, 80)
        parent.btn_join.setCursor(Qt.CursorShape.PointingHandCursor)
        parent.btn_join.setStyleSheet(host_join_button_style) 

        buttons_container_layout.addStretch()
        buttons_container_layout.addWidget(parent.btn_host)
        buttons_container_layout.addSpacing(50)
        buttons_container_layout.addWidget(parent.btn_join)
        buttons_container_layout.addStretch()

        central_hbox_for_buttons = QHBoxLayout()
        central_hbox_for_buttons.addStretch()
        central_hbox_for_buttons.addWidget(buttons_container)
        central_hbox_for_buttons.addStretch()
        home_layout.addLayout(central_hbox_for_buttons)

        home_layout.addSpacerItem(QSpacerItem(20, 100, QSizePolicy.Minimum, QSizePolicy.Expanding))

        parent.home_page.setStyleSheet("""
            background-color: #2e2e2f;
            border-radius: 15px;
            padding: 10px;
        """)
        parent.stacked_widget.addWidget(parent.home_page)

        parent.settings_page = QWidget()
        settings_layout = QVBoxLayout(parent.settings_page)

        parent.top_settings_container = QWidget()
        top_settings_layout = QHBoxLayout(parent.top_settings_container)
        parent.top_settings_container.setStyleSheet("""
            background-color: #4e4e4f; /* Cor de fundo do retângulo */
            border: 1px solid #666; /* Borda */
            border-radius: 8px; /* Bordas arredondadas */
            padding: 10px; /* Espaçamento interno */
        """)

        username_group_layout = QVBoxLayout()
        username_group_layout.setAlignment(Qt.AlignTop | Qt.AlignLeft) 
        username_group_layout.addWidget(QLabel("Nome de Usuário:"))
        parent.username_entry = QLineEdit()
        parent.username_entry.setPlaceholderText("Digite seu nome (padrão: Usuário)")
        parent.username_entry.setFixedWidth(200)  
        parent.username_entry.setStyleSheet("""
            QLineEdit {
                background-color: #3e3e3f;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 5px;
            }
        """)
        username_group_layout.addWidget(parent.username_entry)
        username_group_layout.addStretch() 

        top_settings_layout.addLayout(username_group_layout)
        top_settings_layout.addSpacing(20) 

        ports_group_layout = QVBoxLayout()
        ports_group_layout.setAlignment(Qt.AlignTop | Qt.AlignLeft) 
        
        ports_group_layout.addWidget(QLabel("Porta de Autenticação:"))
        parent.auth_port_entry = QLineEdit()
        parent.auth_port_entry.setPlaceholderText("Ex: 20556")
        parent.auth_port_entry.setFixedWidth(100)  
        parent.auth_port_entry.setStyleSheet("""
            QLineEdit {
                background-color: #3e3e3f;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 5px;
            }
        """)
        ports_group_layout.addWidget(parent.auth_port_entry)

        ports_group_layout.addWidget(QLabel("Porta de Comunicação:"))
        parent.comm_port_entry = QLineEdit()
        parent.comm_port_entry.setPlaceholderText("Ex: 20557")
        parent.comm_port_entry.setFixedWidth(100)  
        parent.comm_port_entry.setStyleSheet("""
            QLineEdit {
                background-color: #3e3e3f;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 5px;
            }
        """)
        ports_group_layout.addWidget(parent.comm_port_entry)
        ports_group_layout.addStretch() 

        top_settings_layout.addLayout(ports_group_layout)
        top_settings_layout.addStretch() 

        settings_layout.addWidget(parent.top_settings_container)
        settings_layout.addStretch() 

        parent.btn_save_settings = QPushButton("Salvar Configurações")
        parent.btn_save_settings.setStyleSheet("""
            QPushButton {
                background-color: #555;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        settings_layout.addWidget(parent.btn_save_settings, alignment=Qt.AlignRight)

        parent.settings_page.setStyleSheet("""
            background-color: #3e3e3f;
            border-radius: 15px;
            padding: 10px;
        """)
        parent.stacked_widget.addWidget(parent.settings_page)

        parent.chat_page = QWidget()
        parent.chat_layout = QVBoxLayout(parent.chat_page) 

        parent.no_chat_label = QLabel("Nenhum chat conectado.")
        parent.no_chat_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font_no_chat = QFont()
        font_no_chat.setPointSize(16)
        parent.no_chat_label.setFont(font_no_chat)
        parent.no_chat_label.setStyleSheet("color: white;") 
        parent.chat_layout.addWidget(parent.no_chat_label)
        parent.chat_layout.addStretch() 

        parent.chat_page.setStyleSheet("""
            background-color: #4e4e4f; /* Cor diferente para o chat */
            border-radius: 15px;
            padding: 10px;
        """)
        parent.stacked_widget.addWidget(parent.chat_page)


        parent.stacked_widget.setCurrentWidget(parent.home_page)

        main_layout.addWidget(sidebar_widget)

        parent.logs_page = QWidget()
        logs_layout = QVBoxLayout(parent.logs_page)

        parent.logs_text_edit = QTextEdit()
        parent.logs_text_edit.setReadOnly(True)
        parent.logs_text_edit.setStyleSheet("""
            background-color: #1e1e1f; /* Fundo escuro como terminal */
            color: #00ff00; /* Texto verde como terminal */
            font-family: "Monospace";
            font-size: 10pt;
            border: none;
            padding: 5px;
        """)
        logs_layout.addWidget(parent.logs_text_edit)

        parent.logs_page.setStyleSheet("""
            background-color: #2e2e2f; /* Cor de fundo da página de logs */
            border-radius: 15px;
            padding: 10px;
        """)
        parent.stacked_widget.addWidget(parent.logs_page)

        parent.stacked_widget.setCurrentWidget(parent.home_page)

        main_layout.addWidget(sidebar_widget)

