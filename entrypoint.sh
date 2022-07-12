#!/bin/bash -l

#set -e

echo "=================="
echo $1
echo "=================="

REPO=$1

#
# Pre-Operation
#
FOUND=`find . -name "*.sol"`
SCAN_LIST=($(echo "${FOUND[0]}" | tr '=' '\n'))
NUM_FOUND=${#SCAN_LIST[@]}
echo "===> number of file to scan = $NUM_FOUND"

#PREFIX="./"
if [[ 0 == $NUM_FOUND ]]; then
        echo "===> nothing to scan..."
else
        for index in "${!SCAN_LIST[@]}"
        do
				#temp=${SCAN_LIST[index]}
				#temp=${temp#"$PREFIX"}
				#SCAN_LIST[index]=$temp
                echo "${SCAN_LIST[index]}"
        done
fi


#
# common
#
sudo apt update
sudo apt install -y software-properties-common
sudo apt install -y libssl-dev python3-dev python3-pip
sudo add-apt-repository -y ppa:ethereum/ethereum
sudo apt install -y solc
wget https://raw.githubusercontent.com/spark63/Spectra/main/conv
chmod +x conv


TOOL_NUM=3
#
# Mythrilp
#
TOOL_ID=0
pip3 install mythril
myth version
for index in "${!SCAN_LIST[@]}"
do
	#myth analyze /github/workspace/${SCAN_LIST[index]} -o json
	myth analyze ${SCAN_LIST[index]} -o json > "result_${TOOL_ID}_${index}.json"
	./conv "create" $TOOL_ID "result_${TOOL_ID}_${index}.json"
done
index=$(( index+1 ))
./conv "merge" $TOOL_ID $index



#
# Slither
#
TOOL_ID=1
pip3 install slither-analyzer
for index in "${!SCAN_LIST[@]}"
do
	slither ${SCAN_LIST[index]} --sarif "result_${TOOL_ID}_${index}.json"
	./conv "create" $TOOL_ID "result_${TOOL_ID}_${index}.json"
done
index=$(( index+1 ))
./conv "merge" $TOOL_ID $index



#
# Semgrep
#
TOOL_ID=2
pip3 install semgrep
semgrep --version
wget https://raw.githubusercontent.com/spark63/Spectra/main/semgrep_rule.zip
unzip semgrep_rule.zip -d rules
for index in "${!SCAN_LIST[@]}"
do
	semgrep --config ./rules ${SCAN_LIST[index]} --sarif --output "result_${TOOL_ID}_${index}_.json"
	jq '.' "result_${TOOL_ID}_${index}_.json" > "result_${TOOL_ID}_${index}.json"
	./conv "create" $TOOL_ID "result_${TOOL_ID}_${index}.json"
done
index=$(( index+1 ))
./conv "merge" $TOOL_ID $index


./conv "generate" $TOOL_NUM

if [ -f "result.sarif" ]; then
	SVAL=$(cat result.sarif | jq --arg rinfo $REPO '. + {repository: $rinfo}')
	echo $SVAL | jq '.' > s.sarif
	curl -X POST --data-binary "@s.sarif" -H "content-type: application/json" "https://spectra.dangun.io:8443/SetAudits" | jq
fi

exit 0
