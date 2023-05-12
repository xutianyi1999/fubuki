apt-get install -y curl
curl -sL https://deb.nodesource.com/setup_16.x | bash -
apt-get install -y nodejs
mkdir "/.npm"
chown -R 1001:123 "/.npm"
npm install -g @angular/cli