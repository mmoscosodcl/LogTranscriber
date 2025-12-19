#!/bin/bash

APP_NAME="logtranscriber"
INSTALL_DIR="/opt/$APP_NAME"
CONFIG_DIR="/etc/$APP_NAME"
BIN_PATH="/usr/local/bin/$APP_NAME"
DEFAULT_LOG_DIR="/var/log/$APP_NAME/raw"
DEFAULT_DATA_DIR="/var/lib/$APP_NAME/data"

function install() {
    if [ "$EUID" -ne 0 ]; then 
        echo "Please run as root"
        exit 1
    fi

    echo "Installing $APP_NAME..."

    # 1. Create Directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DEFAULT_LOG_DIR"
    mkdir -p "$DEFAULT_DATA_DIR"

    # 2. Copy Application Files
    cp app.py "$INSTALL_DIR/"
    cp requirements.txt "$INSTALL_DIR/"
    
    # 3. Setup Virtual Environment
    echo "Setting up virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

    # 4. Setup Configuration
    if [ ! -f "$CONFIG_DIR/config.env" ]; then
        if [ -f "config.env.template" ]; then
            cp config.env.template "$CONFIG_DIR/config.env"
        else
            # Create default config if template missing
            echo "SSH_HOST=" > "$CONFIG_DIR/config.env"
            echo "SSH_USER=" >> "$CONFIG_DIR/config.env"
            echo "SSH_PASS=" >> "$CONFIG_DIR/config.env"
            echo "JWT_SECRET=" >> "$CONFIG_DIR/config.env"
            echo "REMOTE_LOG_PATH=/var/log/nginx/" >> "$CONFIG_DIR/config.env"
            echo "LOCAL_LOG_PATH=$DEFAULT_LOG_DIR/" >> "$CONFIG_DIR/config.env"
            echo "DATA_OUTPUT_PATH=$DEFAULT_DATA_DIR/" >> "$CONFIG_DIR/config.env"
        fi
        echo "Created default configuration at $CONFIG_DIR/config.env"
    else
        echo "Configuration already exists at $CONFIG_DIR/config.env"
    fi
    
    # Secure configuration file
    chmod 600 "$CONFIG_DIR/config.env"

    # 5. Create Binary Wrapper
    cat > "$BIN_PATH" <<EOF
#!/bin/bash
source "$INSTALL_DIR/venv/bin/activate"
python "$INSTALL_DIR/app.py" "\$@"
EOF
    chmod +x "$BIN_PATH"

    echo "Installation complete!"
    echo "Please edit $CONFIG_DIR/config.env with your credentials."
    echo "Run '$APP_NAME' to start."
}

function remove() {
    if [ "$EUID" -ne 0 ]; then 
        echo "Please run as root"
        exit 1
    fi

    echo "Removing $APP_NAME..."

    # Remove Binary
    rm -f "$BIN_PATH"
    
    # Remove App Directory
    rm -rf "$INSTALL_DIR"

    echo "Application removed."
    echo "Note: Configuration ($CONFIG_DIR) and Data ($DEFAULT_DATA_DIR) were NOT removed to preserve data."
    echo "To remove them manually run: rm -rf $CONFIG_DIR $DEFAULT_LOG_DIR $DEFAULT_DATA_DIR"
}

case "$1" in
    install)
        install
        ;;
    remove)
        remove
        ;;
    *)
        echo "Usage: $0 {install|remove}"
        exit 1
        ;;
esac
