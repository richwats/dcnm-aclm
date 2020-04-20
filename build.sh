#!/usr/bin/env bash
sudo git pull
sudo docker build containers/backend -t dcnm_aclm:0.1
cd imagedir/
sudo rm dcnm_aclm_frontend.zip
sudo rm image.tar
cd ../frontend/
sudo zip dcnm_aclm_frontend.zip ./* -r
sudo mv dcnm_aclm_frontend.zip ../imagedir
cd ../imagedir/
sudo docker image save dcnm_aclm:0.1 -o image.tar
cd ../
sudo tar -czvf dcnm_aclm.tar.gz imagedir/
sudo mv dcnm_aclm.tar.gz /home/cisco
