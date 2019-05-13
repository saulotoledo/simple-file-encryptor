#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Simple file encryptor.

Sample application to encrypt files using OpenSSL in PyQt5.

Author: Saulo Toledo
"""

import sys
from PyQt5.QtWidgets import QApplication, QWidget
from PyQt5.QtWidgets import QInputDialog, QLineEdit, QFileDialog

from app import App

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
