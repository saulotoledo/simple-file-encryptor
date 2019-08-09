import os, shlex, subprocess, time
from PyQt5 import uic
from PyQt5.QtWidgets import QMainWindow, QApplication, QMessageBox, QFileDialog

class App(QMainWindow):

    encValues = {
        'Base 64': 'base64',
        'Blowfish in CBC mode': 'bf-cbc',
        'Blowfish in CFB mode': 'bf-cfb',
        'Blowfish in ECB mode': 'bf-ecb',
        'Blowfish in OFB mode': 'bf-ofb',
        'CAST in CBC mode': 'cast-cbc',
        'CAST5 in CBC mode': 'cast5-cbc',
        'CAST5 in CFB mode': 'cast5-cfb',
        'CAST5 in ECB mode': 'cast5-ecb',
        'CAST5 in OFB mode': 'cast5-ofb',
        'DES in CBC mode': 'des-cbc',
        'DES in CFB mode': 'des-cfb',
        'DES in OFB mode': 'des-ofb',
        'DES in ECB mode': 'des-ecb',
        'Two key triple DES EDE in CBC mode': 'des-ede-cbc',
        'Two key triple DES EDE in ECB mode': 'des-ede',
        'Two key triple DES EDE in CFB mode': 'des-ede-cfb',
        'Two key triple DES EDE in OFB mode': 'des-ede-ofb',
        'Three key triple DES EDE in CBC mode': 'des-ede3-cbc',
        'Three key triple DES EDE in ECB mode': 'des-ede3',
        'Three key triple DES EDE CFB mode': 'des-ede3-cfb',
        'Three key triple DES EDE in OFB mode': 'des-ede3-ofb',
        'DESX algorithm': 'desx',
        'GOST 28147-89 in CFB mode (provided by ccgost engine)': 'gost89',
        'GOST 28147-89 in CNT mode (provided by ccgost engine)': 'gost89-cnt',
        '128 bit RC2 in CBC mode': 'rc2-cbc',
        '128 bit RC2 in CFB mode': 'rc2-cfb',
        '128 bit RC2 in ECB mode': 'rc2-ecb',
        '128 bit RC2 in OFB mode': 'rc2-ofb',
        '64 bit RC2 in CBC mode': 'rc2-64-cbc',
        '40 bit RC2 in CBC mode': 'rc2-40-cbc',
        '128 bit RC4': 'rc4',
        '40 bit RC4': 'rc4-40',
        '128 bit AES in CBC mode': 'aes-128-cbc',
        '128 bit AES in 128 bit CFB mode': 'aes-128-cfb',
        '128 bit AES in 1 bit CFB mode': 'aes-128-cfb1',
        '128 bit AES in 8 bit CFB mode': 'aes-128-cfb8',
        '128 bit AES in ECB mode': 'aes-128-ecb',
        '128 bit AES in OFB mode': 'aes-128-ofb',
        '192 bit AES in CBC mode': 'aes-192-cbc',
        '192 bit AES in 128 bit CFB mode': 'aes-192-cfb',
        '192 bit AES in 1 bit CFB mode': 'aes-192-cfb1',
        '192 bit AES in 8 bit CFB mode': 'aes-192-cfb8',
        '192 bit AES in ECB mode': 'aes-192-ecb',
        '192 bit AES in OFB mode': 'aes-192-ofb',
        '256 bit AES in CBC mode': 'aes-256-cbc',
        '256 bit AES in 128 bit CFB mode': 'aes-256-cfb',
        '256 bit AES in 1 bit CFB mode': 'aes-256-cfb1',
        '256 bit AES in 8 bit CFB mode': 'aes-256-cfb8',
        '256 bit AES in ECB mode': 'aes-256-ecb',
        '256 bit AES in OFB mode': 'aes-256-ofb'
    }

    defaultEncMethod = 'aes-256-cbc'
    noPasswordEncMethods = ['base64']

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        uic.loadUi('ui/MainWindow.ui', self)
        self.cbEncryption.addItems(self.encValues.keys())

        self.cbEncryption.setCurrentIndex(list(self.encValues.values()).index(self.defaultEncMethod))
        self.show()

    def actionQuit(self):
        QApplication.quit()

    def selectFile(self):
        filename = QFileDialog.getOpenFileName()[0]
        self.leFile.setText(filename)

    def encryptFile(self):
        if self.__checkRequirements():
            self.__runCommand(False)

    def decryptFile(self):
        if self.__checkRequirements():
            self.__runCommand(True)

    def __checkRequirements(self):
        errorMessage = ''
        filename = self.leFile.text()
        if not filename or not os.path.isfile(filename):
            errorMessage = 'Please select a valid file.'
        elif self.__needsPassword() and not self.lePassword.text():
            errorMessage = 'This encryption method requires a password.'

        if errorMessage:
            msg = QMessageBox()
            msg.setWindowTitle('Missing requirements')
            msg.setIcon(QMessageBox.Critical)
            msg.setText(errorMessage)
            msg.exec_()
            return False

        return True

    def __needsPassword(self):
        enc = self.encValues[str(self.cbEncryption.currentText())]
        if enc in self.noPasswordEncMethods:
            return False
        return True

    def onEncMethodChange(self):
        self.lePassword.setDisabled(not self.__needsPassword)

    def __runCommand(self, decrypt = False):
        enc = self.encValues[str(self.cbEncryption.currentText())]
        filename = self.leFile.text().strip()
        targetFilename = self.__generateTargetFilename(filename, decrypt)

        additionalParams = '-salt'
        if decrypt:
            additionalParams = '-d'

        password = self.lePassword.text()
        passwordParam = ''

        if len(password) > 0:
            passwordParam = '-pass pass:' + password

        commandLine = 'openssl enc -{0} {1} {2} -in "{3}" -out "{4}"'.format(
            enc, additionalParams, passwordParam, filename, targetFilename
        )

        process = subprocess.Popen(
            shlex.split(commandLine),
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE
        )
        stdout, stderr = process.communicate()

        msg = QMessageBox()
        msg.setWindowTitle('Operation finished')
        if process.returncode == 0 and os.path.isfile(targetFilename):
            msg.setIcon(QMessageBox.Information)
            msg.setText('Your file was sucessfully processed at "{0}"!'.format(targetFilename))
            msg.setDetailedText(stderr.decode('utf-8') + "\n" + stdout.decode('utf-8'))
        else:
            msg.setIcon(QMessageBox.Critical)
            msg.setText('An error has occurred. Check your password and encryption method.')
            msg.setDetailedText(stderr.decode('utf-8'))

        msg.exec_()

    def __generateTargetFilename(self, filename, decrypt = False):
        newFilename = filename
        if decrypt:
            if filename.endswith('.enc'):
                newFilename = filename[:-4]
            else:
                newFilename = filename + '.dec'
        else:
            newFilename = filename + '.enc'

        if os.path.isfile(newFilename):
            counter = 1
            tempFilename = newFilename + '.' + str(counter)
            while os.path.isfile(tempFilename):
                counter += 1
                tempFilename = newFilename + '.' + str(counter)

            newFilename = tempFilename

        return newFilename
