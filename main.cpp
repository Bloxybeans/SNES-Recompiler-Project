#include <QApplication>
#include <QMainWindow>
#include <QPushButton>
#include <QListWidget>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include "recompiler.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr)
        : QMainWindow(parent)
    {
        auto *central = new QWidget;
        auto *layout  = new QVBoxLayout;

        addButton     = new QPushButton("Add ROM...");
        compileButton = new QPushButton("Compile Selected");
        romList       = new QListWidget;

        layout->addWidget(addButton);
        layout->addWidget(romList);
        layout->addWidget(compileButton);
        central->setLayout(layout);
        setCentralWidget(central);

        connect(addButton, &QPushButton::clicked, this, &MainWindow::onAddRom);
        connect(compileButton, &QPushButton::clicked, this, &MainWindow::onCompile);
    }

private slots:
    void onAddRom() {
        QString file = QFileDialog::getOpenFileName(
            this,
            "Select SNES ROM",
            QDir::homePath(),
            "SNES ROM Files (*.sfc *.smc)"
        );
        if (!file.isEmpty()) {
            romList->addItem(file);
        }
    }

    void onCompile() {
        auto *item = romList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "No ROM Selected", "Please select a ROM to compile.");
            return;
        }

        QString romPath = item->text();
        QString asmPath = romPath + ".asm";
        bool success = recompileRom(
            romPath.toStdString(),
            asmPath.toStdString()
        );

        if (success) {
            QMessageBox::information(
                this,
                "Compilation Complete",
                QString("ASM output: %1").arg(asmPath)
            );
        } else {
            QMessageBox::critical(
                this,
                "Compilation Failed",
                "An error occurred during recompilation."
            );
        }
    }

private:
    QPushButton *addButton;
    QPushButton *compileButton;
    QListWidget *romList;
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    MainWindow window;
    window.setWindowTitle("SNES-to-x86_64 Recompiler");
    window.resize(500, 400);
    window.show();
    return app.exec();
}
