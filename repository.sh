#!/bin/sh
ARCH=$(uname -m)
PERMISSION=$(whoami)
INSTALL_LIST="build-essential libfontconfig1 mesa-common-dev libglu1-mesa-dev libpcap* libnet1* qt5-qmake qt5-default"
TITLE="If it is finish that download qt and install package files, print out \"Success\""
FINISH="\"Success\""

echo 
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo 
printf "%*s\n" $(((${#TITLE}+$(tput cols))/2)) "$TITLE"
echo 
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo 
#if [ $ARCH = "x86_64" ] ; then
#	FILE="qt-opensource-linux-x64-5.5.1.run"
#else
#	FILE="qt-opensource-linux-x86-5.5.1.run"
#fi

#WGET_FAILED="\"$FILE Download is Failed!! Check your Network!!\""
#FILE_FAILED="\"$FILE is not found!! Check your $ARCH!!\""
#WGET_SUCCESS="\"$FILE found!! Download $FILE...\""
#WGET_CONTINUE="\"$FILE is exist!! $FILE Download continue...\""
SUDO_FAILED="\"You must change permission from user to root! cuz Install Packages!\""
INSTALL_SUCCESS="\"Packages install finished!! Now we build yummyKit tool...\""
BUILD_SUCCESS="\"Build finished!! Now, you can run yummyKit tool. Input in terminal \"sudo ./yummyKit\" Just do it!\""
BUILD_FAILED="\"Build failed.. No such libnet-header.h file in libnet directory.\"" 
#if [ ! -e $FILE ] ; then
#	echo "\n"
#	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
#	echo "\n"
#	printf "%*s\n" $(((${#WGET_SUCCESS}+$(tput cols))/2)) "$WGET_SUCCESS"
#	echo "\n"
#	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
#	echo "\n"
#	wget https://download.qt.io/archive/qt/5.5/5.5.1/$FILE
#	CHECK=$(ls | grep $FILE)
#elif [ -e $FILE ] ; then
#	echo "\n"
#	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
#	echo "\n"
#	printf "%*s\n" $(((${#WGET_CONTINUE}+$(tput cols))/2)) "$WGET_CONTINUE"
#	echo "\n"
#	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
#	echo "\n"
#	wget -c https://download.qt.io/archive/qt/5.5/5.5.1/$FILE
#	CHECK=$(ls | grep $FILE)
#else
#	echo "\n"
#	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
#	echo "\n"
#	printf "%*s\n" $(((${#FILE_FAILED}+$(tput cols))/2)) "$FILE_FAILED"
#	echo "\n"
#	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
#	echo "\n"
#fi

#if [ CHECK ] ; then
#	FAST_GUI="function Controller() {\n\t\
#		installer.autoRejectMessageBoxes();\n\t\
#		installer.installationFinished.connect(function() {\n\t\t\
#			gui.clickButton(buttons.NextButton);\n\t\
#		})\n\
#	}\n\
#	Controller.prototype.WelcomePageCallback = function() {\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.CredentialsPageCallback = function() {\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.IntroductionPageCallback = function() {\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.TargetDirectoryPageCallback = function() {\n\t\
#		gui.currentPageWidget().TargetDirectoryLineEdit.setText(\"/opt/Qt5.5.1\");\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.ComponentSelectionPageCallback = function() {\n\t\
#		var widget = gui.currentPageWidget();\n\t\
#		widget.deselectAll();\n\t\
#		widget.selectComponent(\"qt.55.gcc_64\");\n\t\
#		widget.selectComponent(\"qt.55.qtquickcontrols\");\n\t\
#		widget.selectComponent(\"qt.tools.qtcreator\");\n\t\
#		widget.selectComponent(\"qt.55.qtlocation\");\n\t\
#		widget.selectComponent(\"qt.55.qtquick1\");\n\t\
#		widget.selectComponent(\"qt.55.qtscript\");\n\t\
#		widget.selectComponent(\"qt.55.qtwebengine\");\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.LicenseAgreementPageCallback = function() {\n\t\
#		gui.currentPageWidget().AcceptLicenseRadioButton.setChecked(true);\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.StartMenuDirectoryPageCallback = function() {\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.ReadyForInstallationPageCallback = function() {\n\t\
#		gui.clickButton(buttons.NextButton);\n\
#	}\n\
#	Controller.prototype.FinishedPageCallback = function() {\n\t\
#		var checkBoxForm = gui.currentPageWidget().LaunchQtCreatorCheckBoxForm\n\t\
#		if (checkBoxForm && checkBoxForm.launchQtCreatorCheckBox) {\n\t\t\
#			checkBoxForm.launchQtCreatorCheckBox.checked = false;\n\t\
#		}\n\t\
#		gui.clickButton(buttons.FinishButton);\n\
#	}"
#	echo $FAST_GUI > ./qt-fast-installer-gui.qs
#	chmod +x ./$FILE
#	./$FILE --script ./qt-fast-installer-gui.qs
if [ "$PERMISSION" = "root" ] ; then
	sudo apt-get update > /dev/null 2>&1 && sudo apt-get -y install $INSTALL_LIST > /dev/null 2>&1
	if [ "$ARCH" = "x86_64" ] ; then
		sudo rm /usr/bin/qmake && sudo ln -s /usr/lib/x86_64-linux-gnu/qt5/bin/qmake /usr/bin/qmake
	else
		sudo rm /usr/bin/qmake && sudo ln -s /usr/lib/i386-linux-gnu/qt5/bin/qmake /usr/bin/qmake
	fi
	echo 
	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
	echo 
	printf "%*s\n" $(((${#INSTALL_SUCCESS}+$(tput cols))/2)) "$INSTALL_SUCCESS"
	echo 
#	mkdir ./build && mv ./Makefile ./build
#	sudo rm ./$FILE ./qt-fast-installer-gui.qs
	if [ -f "/usr/include/libnet/libnet-headers.h" ] && [ $(cat "/usr/include/libnet/libnet-headers.h" 2>/dev/null | grep -i "address information allocated dynamically" | wc -l) -eq 1 ]; then
		libnet_header=$(cat "/usr/include/libnet/libnet-headers.h" | sed -e 's/\/\*\ address\ information\ allocated\ dynamically\ \*\//u_char ar_sha[6], ar_spa[4], ar_dha[6], ar_dpa[4];/g')
		echo "$libnet_header" > /usr/include/libnet/libnet-headers.h
		make > /dev/null 2>&1 && sudo rm *.cpp *.o *.h
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo 
		printf "%*s\n" $(((${#BUILD_SUCCESS}+$(tput cols))/2)) "$BUILD_SUCCESS"
		echo 
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo 
		printf "%*s\n" $(((${#FINISH}+$(tput cols))/2)) "$FINISH"
		echo 
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo
	elif [ -f "/usr/include/libnet/libnet-headers.h" ]; then 
		make > /dev/null 2>&1 && sudo rm *.cpp *.o *.h
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo 
		printf "%*s\n" $(((${#BUILD_SUCCESS}+$(tput cols))/2)) "$BUILD_SUCCESS"
		echo 
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo 
		printf "%*s\n" $(((${#FINISH}+$(tput cols))/2)) "$FINISH"
		echo 
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo
	else
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo 
		printf "%*s\n" $(((${#BUILD_FAILED}+$(tput cols))/2)) "$BUILD_FAILED"
		echo 
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo
	fi
else
	echo 
	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
	echo 
#	printf "%*s\n" $(((${#WGET_FAILED}+$(tput cols))/2)) "$WGET_FAILED"
	printf "%*s\n" $(((${#SUDO_FAILED}+$(tput cols))/2)) "$SUDO_FAILED"
	echo 
	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
	echo 
fi
