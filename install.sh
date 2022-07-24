echo "Installing"
wget https://github.com/Rajveer2009/check/raw/main/check_2_1_amd64.deb
sudo dpkg --install check_2_1_amd64.deb
echo "Install Finish"
check --version
