#!/bin/bash

# Variables
GIT_REPO_URL="https://github.com/Scout-lander/unraidMatrix/"
MATRIX_LOGIN_FILE="matrix_login.php"
LOGIN_FILE_PATH="/usr/local/emhttp/webGui/include/.login.php"
BACKUP_FILE_PATH="/usr/local/emhttp/webGui/include/.login_backup.php"
TEMP_DIR="/tmp/matrix_login"
INSTALL=true  # Set to true to install Matrix login, false to restore backup

if [ "$INSTALL" = true ]; then
    # Step 1: Back up the original login file
    if [ ! -f "$BACKUP_FILE_PATH" ]; then
        echo "Backing up the original login file..."
        cp "$LOGIN_FILE_PATH" "$BACKUP_FILE_PATH"
        echo "Backup created at $BACKUP_FILE_PATH"
    else
        echo "Backup already exists at $BACKUP_FILE_PATH"
    fi

    # Step 2: Clone the Git repository
    if [ -d "$TEMP_DIR" ]; then
        echo "Cleaning up existing temporary directory..."
        rm -rf "$TEMP_DIR"
    fi

    echo "Cloning the Matrix login repository..."
    git clone "$GIT_REPO_URL" "$TEMP_DIR"

    if [ $? -ne 0 ]; then
        echo "Failed to clone the repository. Exiting."
        exit 1
    fi

    # Step 3: Replace the login file
    if [ -f "$TEMP_DIR/$MATRIX_LOGIN_FILE" ]; then
        echo "Replacing the login file with the Matrix-themed login..."
        cp "$TEMP_DIR/$MATRIX_LOGIN_FILE" "$LOGIN_FILE_PATH"
        echo "Matrix login installed successfully."
    else
        echo "Matrix login file not found in the repository. Exiting."
        exit 1
    fi

    # Step 4: Clean up temporary directory
    echo "Cleaning up..."
    rm -rf "$TEMP_DIR"
    echo "Installation complete."
else
    # Restore the backup
    if [ -f "$BACKUP_FILE_PATH" ]; then
        echo "Restoring the original login file from backup..."
        cp "$BACKUP_FILE_PATH" "$LOGIN_FILE_PATH"
        echo "Original login file restored successfully."
    else
        echo "Backup file not found. Cannot restore the original login file."
        exit 1
    fi
fi
