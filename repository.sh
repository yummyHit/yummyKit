#!/bin/bash
ARCH=$(uname -m)
PERMISSION=$(whoami)

if [ "$(cat /etc/*-release | egrep -i '(ubuntu|suse|debian|kali|oracle\ linux)')" != "" ]; then
	if [ "$(cat /etc/*-release | grep -i 'ubuntu')" != "" ]; then
		OS_NAME="Ubuntu"
	elif [ "$(cat /etc/*-release | grep -i 'suse')" != "" ]; then
		OS_NAME="SuSE"
	elif [ "$(cat /etc/*-release | grep -i 'kali')" != "" ]; then
		OS_NAME="Kali"
	elif [ "$(cat /etc/*-release | grep -i 'debian')" != "" ]; then
		OS_NAME="Debian"
	else
		OS_NAME="Oracle"
	fi

	OS_VERSION=$(cat /etc/os-release | grep -i "VERSION_ID" | cut -d '=' -f2- | sed -e 's/\"//g')
elif [ "$(cat /etc/*-release | egrep -i '(centos|fedora|red\ hat\ enterprise)')" != "" ]; then
	if [ "$(cat /etc/*-release | grep -i 'centos')" != "" ]; then
		OS_NAME="CentOS"
	elif [ "$(cat /etc/*-release | grep -i 'fedora')" != "" ]; then
		OS_NAME="Fedora"
	else
		OS_NAME="RHEL"
	fi

	OS_VERSION=$(cat /etc/redhat-release | awk '{ print $3 }')
fi

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
APT_FAILED="\"packages install failed.. Isn't dpkg(or yum) locked or archive cache locked on your system?\""
APT_SUCCESS=
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
	if [ "${OS_NAME}" = "Ubuntu" ] || [ "${OS_NAME}" = "Kali" ] || [ "${OS_NAME}" = "Debian" ]; then	# Need to Kali, Debian version test
		if [ "$(echo $OS_VERSION | tr '.' ' ' | awk '{ print $1 }')" -le "12" ]; then
			INSTALL_LIST="build-essential libfontconfig1 mesa-common-dev libglu1-mesa-dev libpcap* libnet1-* qtdeclarative5-dev"
			echo | sudo apt-add-repository ppa:canonical-qt5-edgers/ubuntu1204-qt5
			sudo apt-get update > /dev/null 2>&1 && sudo apt-get -y install $INSTALL_LIST > /dev/null 2>&1 && APT_SUCCESS="SUCCESS"
		else
			INSTALL_LIST="build-essential libfontconfig1 mesa-common-dev libglu1-mesa-dev libpcap* libnet1-* qt5-qmake qt5-default"
			sudo apt-get update > /dev/null 2>&1 && sudo apt-get -y install $INSTALL_LIST > /dev/null 2>&1 && APT_SUCCESS="SUCCESS"
		fi
	elif [ "${OS_NAME}" = "Fedora" ]; then
		INSTALL_LIST="libpcap* gcc-c++ freetype freetype-devel fontconfig fontconfig-devel libstdc++ mesa-libGL mesa-libGL-devel libdrm-devel libX11-devel libnet* qt5-qtdeclarative-devel"
		sudo yum update > /dev/null 2>&1 && sudo yum -y groupinstall 'Development Tools' > /dev/null 2>&1 && sudo yum -y install $INSTALL_LIST > /dev/null 2>&1 && APT_SUCCESS="SUCCESS"
	elif [ "${OS_NAME}" = "CentOS" ]; then
		if [ "$(echo $OS_VERSION | tr '.' ' ' | awk '{ print $1 }')" -le "5" ]; then
			sudo rpm -Uvh http://archives.fedoraproject.org/pub/archive/epel/5/x86_64/epel-release-5-4.noarch.rpm
			INSTALL_LIST="libpcap* gcc-c++ freetype freetype-devel fontconfig fontconfig-devel libstdc++ mesa-libGL mesa-libGL-devel libdrm-devel libX11-devel libnet* qt5-qtdeclarative-devel"
			sudo yum update > /dev/null 2>&1 && sudo yum --enablerepo=extras install -y epel-release > /dev/null 2>&1 && sudo yum -y groupinstall 'Development Tools' --skip-broken > /dev/null 2>&1 && sudo yum -y install $INSTALL_LIST > /dev/null 2>&1 && APT_SUCCESS="SUCCESS"
		else
			INSTALL_LIST="libpcap* gcc-c++ freetype freetype-devel fontconfig fontconfig-devel libstdc++ mesa-libGL mesa-libGL-devel libdrm-devel libX11-devel libnet* qt5-qtdeclarative-devel"
			sudo yum update > /dev/null 2>&1 && sudo yum --enablerepo=extras install -y epel-release > /dev/null 2>&1 && sudo yum -y groupinstall 'Development Tools' --skip-broken > /dev/null 2>&1 && sudo yum -y install $INSTALL_LIST > /dev/null 2>&1 && APT_SUCCESS="SUCCESS"
		fi
	fi

	if [ "$APT_SUCCESS" = "SUCCESS" ]; then
		FIND_QMAKE_BIN=$(find /usr/lib/ /usr/lib64/ -name "qmake" -type f 2>/dev/null | grep "qt5" | awk 'NR==1{print $1}')
		sudo rm /usr/bin/qmake 2>/dev/null; sudo ln -s $FIND_QMAKE_BIN /usr/bin/qmake
		FIND_CPP_DIR=$(find /usr/include/ -name "c++" -type d -exec ls -d {} \; 2>/dev/null | grep -v "linux-gnu")
		FIND_CPP_VERSION_DIR=$(echo "$FIND_CPP_DIR/$(ls $FIND_CPP_DIR | sort -n | tail -1)" | sed -e 's/\//\\\//g')
		FIND_GCC_INC_DIR=$(find /usr/lib/gcc/ -name "include" -type d -exec dirname {} \; 2>/dev/null | tail -1 | sed -e 's/\//\\\//g')
		if [ "${OS_NAME}" = "Ubuntu" ] || [ "${OS_NAME}" = "Kali" ] || [ "${OS_NAME}" = "Debian" ]; then
			if [ "$ARCH" = "x86_64" ] ; then
				make_file=$(cat $(pwd)/Makefile | sed -e 's/QT_LIB_DIR_TO_SHELL/\/usr\/lib\/x86_64-linux-gnu\/qt5/g' -e 's/QT_INC_DIR_TO_SHELL/\/usr\/include\/x86_64-linux-gnu\/qt5/g' -e 's/UBUNTU_CPP_DIR_TO_SHELL/-I\/usr\/include\/x86_64-linux-gnu\/c++\/5/g' -e 's/UBUNTU_GNU_DIR_TO_SHELL/-I\/usr\/include\/x86_64-linux-gnu/g' -e 's/GCC_LIB_DIR_TO_SHELL/'$FIND_GCC_INC_DIR'/g' -e 's/LIB_DIR_TO_SHELL/\/usr\/lib\/x86_64-linux-gnu/g' -e 's/CPP_DIR_TO_SHELL/'$FIND_CPP_VERSION_DIR'/g')
			else
				make_file=$(cat $(pwd)/Makefile | sed -e 's/QT_LIB_DIR_TO_SHELL/\/usr\/lib\/i386-linux-gnu\/qt5/g' -e 's/QT_INC_DIR_TO_SHELL/\/usr\/include\/i386-linux-gnu\/qt5/g' -e 's/UBUNTU_CPP_DIR_TO_SHELL/-I\/usr\/include\/i386-linux-gnu\/c++\/5/g' -e 's/UBUNTU_GNU_DIR_TO_SHELL/-I\/usr\/include\/x86_64-linux-gnu/g' -e 's/GCC_LIB_DIR_TO_SHELL/'$FIND_GCC_INC_DIR'/g' -e 's/LIB_DIR_TO_SHELL/\/usr\/lib\/i386-linux-gnu/g' -e 's/CPP_DIR_TO_SHELL/'$FIND_CPP_VERSION_DIR'/g')
			fi

			echo "$make_file" > $(pwd)/Makefile
		elif [ "${OS_NAME}" = "Fedora" ] || [ "${OS_NAME}" = "CentOS" ]; then
			if [ "$ARCH" = "x86_64" ]; then
				make_file=$(cat $(pwd)/Makefile | sed -e 's/QT_LIB_DIR_TO_SHELL/\/usr\/lib64\/qt5/g' -e 's/QT_INC_DIR_TO_SHELL/\/usr\/include\/qt5/g' -e 's/UBUNTU_CPP_DIR_TO_SHELL//g' -e 's/UBUNTU_GNU_DIR_TO_SHELL//g' -e 's/GCC_LIB_DIR_TO_SHELL/'$FIND_GCC_INC_DIR'/g' -e 's/LIB_DIR_TO_SHELL/\/usr\/lib64/g' -e 's/CPP_DIR_TO_SHELL/'$FIND_CPP_VERSION_DIR'/g')
			else
				make_file=$(cat $(pwd)/Makefile | sed -e 's/QT_LIB_DIR_TO_SHELL/\/usr\/lib\/qt5/g' -e 's/QT_INC_DIR_TO_SHELL/\/usr\/include\/qt5/g' -e 's/UBUNTU_CPP_DIR_TO_SHELL//g' -e 's/UBUNTU_GNU_DIR_TO_SHELL//g' -e 's/GCC_LIB_DIR_TO_SHELL/'$FIND_GCC_INC_DIR'/g' -e 's/LIB_DIR_TO_SHELL/\/usr\/lib/g' -e 's/CPP_DIR_TO_SHELL/'$FIND_CPP_VERSION_DIR'/g')
			fi

			echo "$make_file" > $(pwd)/Makefile
		fi

		echo 
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo 
		printf "%*s\n" $(((${#INSTALL_SUCCESS}+$(tput cols))/2)) "$INSTALL_SUCCESS"
		echo 
	#	mkdir ./build && mv ./Makefile ./build
	#	sudo rm ./$FILE ./qt-fast-installer-gui.qs
		FIND_LIBNET_HEADER=$(find /usr/include/ -name "libnet-headers.h" -type f 2>/dev/null | tail -1)
		if [ -f "$FIND_LIBNET_HEADER" ] && [ $(cat "$FIND_LIBNET_HEADER" 2>/dev/null | grep -i "address information allocated dynamically" | wc -l) -eq 1 ]; then
			libnet_header=$(cat "$FIND_LIBNET_HEADER" | sed -e 's/\/\*\ address\ information\ allocated\ dynamically\ \*\//u_char ar_sha[6], ar_spa[4], ar_dha[6], ar_dpa[4];/g')
			echo "$libnet_header" > $FIND_LIBNET_HEADER
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
		elif [ -f "$FIND_LIBNET_HEADER" ]; then 
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
		printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
		echo 
		printf "%*s\n" $(((${#APT_FAILED}+$(tput cols))/2)) "$APT_FAILED"
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
