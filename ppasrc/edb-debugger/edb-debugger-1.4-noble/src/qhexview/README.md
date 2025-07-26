A Qt widget designed to give a nice looking but traditional hex view.

![Screenshot](http://codef00.com/img/qhexview.png)

Basic usage is trivial. Any `QIODevice` can be a data source for the widget. For example:

	#include "QHexView"
	#include <QApplication>
	#include <QFile>

	int main(int argc, char *argv[]) {
		QApplication app(argc, argv);

		QHexView w;
		QFile file(argv[1]);
		file.open(QIODevice::ReadOnly);

		w.setData(&file);
		w.show();
		app.exec();
		return 0;
	}

This is a complete program which will display in a nice hex view, the contents of a file.
