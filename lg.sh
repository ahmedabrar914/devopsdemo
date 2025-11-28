#!/bin/bash

PROJECT_ID="hbl-dev-ef-blr-prj-spk-5a"
config_file="/opt/perfteam/LGs_VM.txt"

while IFS=' ' read -r instance zone vm_type vm_ip; do

    if [ -n "$instance" ] && [ -n "$zone" ] && [ -n "$vm_type" ] && [ -n "$vm_ip" ]; then
        if [ "$vm_type" == "lg" ]; then

            echo "Starting VM: $instance"

            gcloud compute instances start "$instance" \
                --project="$PROJECT_ID" \
                --zone="$zone"

            if [ $? -eq 0 ]; then
                echo "LG VM Started: $instance"
            else
                echo "Failed"
            fi

        fi
    fi

done < "$config_file"