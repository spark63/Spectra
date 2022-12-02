package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	//"strings"
	"conv/common"
	"conv/converter/conv1"
	"conv/converter/conv2"
	"conv/converter/conv3"
	)
/*
//-------------------------------------------------------------------
// Mythril's result
//-------------------------------------------------------------------
type Issue struct {
	Code		string	`json:"code"`
	Contract	string	`json:"contract"`
	Description	string	`json:"description"`
	FileName	string	`json:"filename"`
	Function	string	`json:"function"`
	LineNo		int	`json:"lineno"`
	Severity	string	`json:"severity"`
	SWC		string	`json:"swc-id"`
	Title		string	`json:"title"`
}

type RawResult struct {
	Error 		string	`json:"error"`
	Issues		[]Issue	`json:"issues"`
	Success		bool	`json:"success"`
}
*/
/*
//-------------------------------------------------------------------
// SARIF format
//-------------------------------------------------------------------
type SDesc struct {
	Text			string		`json:"text"`
}

type FDesc struct {
	Text			string		`json:"text"`
}

type Help struct {
	Text			string		`json:"text"`
	Markdown		string		`json:"markdown"`	// markdown is available, it is displayed instead of help.text
}

type Property struct {
	ProblemSeverity		string		`json:"problem.severity"`	// error, warning, recommendation
	SecuritySeverity	string		`json:"security-severity"`	// critical : > 9.0, high : 7.0 ~ 8.9, medium : 4.0 ~ 6.9, low : <= 3.9 
}

type Rule struct {
	ID			string		`json:"id"`
	Name			string		`json:"name"`
	ShortDescription	SDesc		`json:"shortDescription"`
	FullDescription		FDesc		`json:"fullDescription"`
	HelpInfo		Help		`json:"help"`
	Properties		Property	`json:"properties"`
}

type Driver struct {
	Name			string		`json:"name"`
	Rules			[]Rule		`json:"rules"`
}

type Msg struct {
	Text			string		`json:"text"`
}

type ALocation struct {
	Uri			string		`json:"uri"`	// a file in the repository
}

type RegionInfo struct {
	StartLine		int		`json:"startLine"`
	//StartComuln		int		`json:"startColumn"`
	//EndLine			int		`json:"endLine"`
	//EndColumn		int		`json:"endColumn"`
}

type PLocation struct {
	ArtifactLocation	ALocation	`json:"artifactLocation"`
	Region			RegionInfo	`json:"region"`
}

type Location struct {
	PhysicalLocation	PLocation	`json:"physicalLocation"`
}

type FingerPrint struct {
	PrimaryLocationLineHash	string		`json:"primaryLocationLineHash"`
}

type Result struct {
	RuleID			string		`json:"ruleId"`
	Message			Msg		`json:"message"`
	Locations		[]Location	`json:"locations"`	// maximum of 10
	//PartialFingerprints	FingerPrint	`json:"partialFingerprints"`
}

type Analyzer struct {
	ToolInfo		Driver		`json:"driver"`
}

type Run struct {
	Tool			Analyzer	`json:"tool"`
	Results			[]Result	`json:"results"`	// maximum of 5000 results, 10 MB
}

type SARIF struct {
	Schema			string		`json:"$schema"`
	Version			string		`json:"version"`
	Runs			[]Run		`json:"runs"`
}
*/
/*
//-------------------------------------------------------------------
// showResult
//-------------------------------------------------------------------
func showResult(result RawResult) {

	len := len(result.Issues)

	for i := 0; i < len; i++ {
		issue := result.Issues[i]
		fmt.Println()
		fmt.Printf("-------[ detected %d ] --------------------------------\n", i+1)
		fmt.Printf("  title       : %s\n", issue.Title)
		fmt.Printf("  contract    : %s\n", issue.Contract)
		fmt.Printf("  file        : %s\n", issue.FileName)
		fmt.Printf("  function    : %s\n", issue.Function)
		fmt.Printf("  code        : %s\n", issue.Code)
		fmt.Printf("  line no     : %d\n", issue.LineNo)
		fmt.Printf("  severity    : %s\n", issue.Severity)
		fmt.Printf("  SWC         : %s\n", issue.SWC)
		fmt.Printf("  description : %s\n", issue.Description)
	}
	fmt.Printf("-------------------------------------------------------\n")
}
*/

//-------------------------------------------------------------------
// doCreate
//-------------------------------------------------------------------
func doCreate(tool_index int, result_file string) bool {

	if 0 == tool_index {
		return conv1.DoCreate(result_file)
	} else if 1 == tool_index {
		return conv2.DoCreate(result_file)
	} else if 2 == tool_index {
		return conv3.DoCreate(result_file)
	}

	return false
	/*
	data, err := ioutil.ReadFile(result_file)
        if err != nil {
                fmt.Printf("===> file read error : %s\n", result_file)
                return false
        }

        //data_string := string(data)
        //fmt.Println(data_string)

        var rawResult RawResult
        err = json.Unmarshal(data, &rawResult)
        if err != nil {
                fmt.Printf("===> file unmarshal failed : %s\n", err.Error())
		return false
        }
        //fmt.Printf("%+v\n", rawResult)

        if rawResult.Success != true {
                fmt.Printf("===> analysys failed : %s\n", rawResult.Error)
                return false
        }

        if rawResult.Error != "" {
                fmt.Printf("===> failed result\n")
                return false
        }

        len := len(rawResult.Issues)
        if len == 0 {
                fmt.Printf("===> empty result\n")
                return false
        }

        //showResult(rawResult)

        return convertToSarif(rawResult, tool_index, len, result_file)
	*/
}


//-------------------------------------------------------------------
// doMerge
//-------------------------------------------------------------------
func doMerge(sarif *common.SARIF, sarif_member common.SARIF, tool_index int) bool {

	num := len(sarif_member.Runs[0].Results)

        for i := 0; i < num; i++ {
                var result common.Result
                member_result := sarif_member.Runs[0].Results[i]

                result.RuleID       = member_result.RuleID
                result.Message.Text = member_result.Message.Text
                result.Locations    = make([]common.Location, 1)
                result.Locations[0].PhysicalLocation.ArtifactLocation.Uri = member_result.Locations[0].PhysicalLocation.ArtifactLocation.Uri
                result.Locations[0].PhysicalLocation.Region.StartLine     = member_result.Locations[0].PhysicalLocation.Region.StartLine
		result.Locations[0].PhysicalLocation.Region.EndLine       = member_result.Locations[0].PhysicalLocation.Region.EndLine

		sarif.Runs[0].Results = append(sarif.Runs[0].Results, result)
        }

	data, err := json.MarshalIndent(sarif, "", "  ")
        if err != nil {
		fmt.Printf("===> (tool : %d) marshal failed : %s\n", tool_index, err.Error())
                return false
        }
        //fmt.Println(string(data))

	sarif_file := "result_" + strconv.Itoa(tool_index) + ".sarif"
	err = ioutil.WriteFile(sarif_file, data, 0644)
        if err != nil {
		fmt.Printf("===> (tool : %d) create merged sarif file failed : %s\n", tool_index, err.Error())
                return false
        }

	fmt.Printf("===> (tool : %d) merge sarif file : %s\n", tool_index, sarif_file)

	return true
}


//-------------------------------------------------------------------
// doSelfMerge
//-------------------------------------------------------------------
func doSelfMerge(sarif common.SARIF, tool_index, file_index int) bool {

	file_name := "result_" + strconv.Itoa(tool_index) + "_" + strconv.Itoa(file_index) + ".sarif"

	_, err := os.Stat(file_name)
        if err != nil {
		fmt.Printf("===> (tool : %d) create self merged sarif file failed : %s\n", tool_index, err.Error())
		return false
	}

        data, err := ioutil.ReadFile(file_name)
        if err != nil {
		fmt.Printf("===> (tool : %d) create self merged sarif file failed : %s\n", tool_index, err.Error())
		return false
        }

        //fmt.Println(string(data))

        sarif_file := "result_" + strconv.Itoa(tool_index) + ".sarif"
        err = ioutil.WriteFile(sarif_file, data, 0644)
        if err != nil {
		fmt.Printf("===> (tool : %d) create self merged sarif file failed : %s\n", tool_index, err.Error())
                return false
        }

	fmt.Printf("===> (tool : %d) self merge sarif file : %s\n", tool_index, sarif_file)

        return true
}

//-------------------------------------------------------------------
// doGenerate
//-------------------------------------------------------------------
func doGenerate(sarif *common.SARIF, sarif_member common.SARIF, t int) bool {

	var run common.Run
	sarif.Runs = append(sarif.Runs, run)

	sarif.Runs[t].Tool.ToolInfo.Name = sarif_member.Runs[0].Tool.ToolInfo.Name
	num_rule := len(sarif_member.Runs[0].Tool.ToolInfo.Rules)
        sarif.Runs[t].Tool.ToolInfo.Rules = make([]common.Rule, num_rule)

        rules := sarif.Runs[t].Tool.ToolInfo.Rules

	for i := 0; i < num_rule; i++ {
		rules[i] = sarif_member.Runs[0].Tool.ToolInfo.Rules[i]
	}

	num := len(sarif_member.Runs[0].Results)
	sarif.Runs[t].Results = make([]common.Result, num)

	results := sarif.Runs[t].Results

	for i := 0; i < num; i++ {
                member_result := sarif_member.Runs[0].Results[i]

                results[i].RuleID       = member_result.RuleID
                results[i].Message.Text = member_result.Message.Text
                results[i].Locations    = make([]common.Location, 1)
                results[i].Locations[0].PhysicalLocation.ArtifactLocation.Uri = member_result.Locations[0].PhysicalLocation.ArtifactLocation.Uri
                results[i].Locations[0].PhysicalLocation.Region.StartLine     = member_result.Locations[0].PhysicalLocation.Region.StartLine
		results[i].Locations[0].PhysicalLocation.Region.EndLine       = member_result.Locations[0].PhysicalLocation.Region.EndLine
        }

	data, err := json.MarshalIndent(sarif, "", "  ")
        if err != nil {
                fmt.Printf("===> generate marshal failed : %s\n", err.Error())
                return false
        }
        //fmt.Println(string(data))

        sarif_file := "result.sarif"
        err = ioutil.WriteFile(sarif_file, data, 0644)
        if err != nil {
                fmt.Printf("===> generate sarif file failed : %s\n", err.Error())
                return false
        }

        fmt.Printf("===> generate sarif file : %s\n", sarif_file)

        return true
}


//-------------------------------------------------------------------
// doSelfGenerate
//-------------------------------------------------------------------
func doSelfGenerate(sarif common.SARIF, tool_index int) bool {

        file_name := "result_" + strconv.Itoa(tool_index) + ".sarif"

	_, err := os.Stat(file_name)
        if err != nil {
		fmt.Printf("===> (tool : %d) generate self sarif file failed : %s\n", tool_index, err.Error())
                return false
        }

        data, err := ioutil.ReadFile(file_name)
        if err != nil {
		fmt.Printf("===> (tool : %d) generate self sarif file failed : %s\n", tool_index, err.Error())
                return false
        }

        //fmt.Println(string(data))

        sarif_file := "result.sarif"
        err = ioutil.WriteFile(sarif_file, data, 0644)
        if err != nil {
		fmt.Printf("===> (tool : %d) generate self sarif file failed : %s\n", tool_index, err.Error())
                return false
        }

	fmt.Printf("===> (tool : %d) generate self sarif file : %s\n", tool_index, sarif_file)

        return true
}


//-------------------------------------------------------------------
// makeEmptySarif
//-------------------------------------------------------------------
func makeEmptySarif() bool {

	data := []byte(`{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": " ",
          "rules": []
        }
      },
      "results": []
    }
  ]
}`)
	sarif_file := "result.sarif"

	err := ioutil.WriteFile(sarif_file, data, 0644)
        if err != nil {
                fmt.Printf("===> make empty sarif file failed : %s\n", err.Error())
                return false
        }

        fmt.Printf("===> make empty sarif file : %s\n", sarif_file)

        return true
}


//-------------------------------------------------------------------
// main
//-------------------------------------------------------------------
func main() {

	if 3 != len(os.Args) && 4 != len(os.Args) {
		fmt.Printf("===> invalid parameter\n")
		return
	}

	if "create" != os.Args[1] && "merge" != os.Args[1] && "generate" != os.Args[1] {
		fmt.Printf("===> invalid parameter\n")
                return
	}

	if "create" == os.Args[1] {
		tool_index, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Printf("===> invalid parameter\n")
			return
		}
		result_file := os.Args[3]
		doCreate(tool_index, result_file)

	} else if "merge" == os.Args[1] {
		tool_index, err := strconv.Atoi(os.Args[2])
                if err != nil {
                        fmt.Printf("===> invalid parameter\n")
                        return
                }
		num_merge, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Printf("===> invalid parameter\n")
			return
		}
		//fmt.Println(num_merge)

		var sarif common.SARIF
		isFirst := true
		merged := false
		firstIndex := -1
		for i := 0; i < num_merge; i++ {
			file_name := "result_" + strconv.Itoa(tool_index) + "_" + strconv.Itoa(i) + ".sarif"

			_, err = os.Stat(file_name)
			if err != nil {
				continue
			}

			data, err := ioutil.ReadFile(file_name)
			if err != nil {
				continue
			}
			var sarif_member common.SARIF
			err = json.Unmarshal(data, &sarif_member)
			if err != nil {
				continue
			}

			if true == isFirst {
				isFirst = false
				sarif = sarif_member
				firstIndex = i
				continue
			}

			if true == doMerge(&sarif, sarif_member, tool_index) {
				merged = true
			}
		}

		if firstIndex != -1 && merged == false {
			doSelfMerge(sarif, tool_index, firstIndex)
		}

	} else if "generate" == os.Args[1] {
		tool_num, err := strconv.Atoi(os.Args[2])
                if err != nil {
                        fmt.Printf("===> invalid parameter\n")
                        return
                }

		var sarif common.SARIF
		isFirst := true
		merged := false
                firstIndex := -1
		for i := 0; i < tool_num; i++ {
			file_name := "result_" + strconv.Itoa(i) + ".sarif"

			_, err = os.Stat(file_name)
                        if err != nil {
                                continue
                        }

			data, err := ioutil.ReadFile(file_name)
                        if err != nil {
                                continue
                        }
                        var sarif_member common.SARIF
                        err = json.Unmarshal(data, &sarif_member)
                        if err != nil {
                                continue
                        }

                        if true == isFirst {
                                isFirst = false
                                sarif = sarif_member
                                firstIndex = i
				continue
                        }

			if true == doGenerate(&sarif, sarif_member, i) {
				merged = true
			}
		}

		if firstIndex != -1 && merged == false {
			doSelfGenerate(sarif, firstIndex)
		}

		_, err = os.Stat("result.sarif")
		if err != nil {
			makeEmptySarif()
		}
	} else {
		fmt.Printf("===> invalid parameter\n")
	}
}

/*
//-------------------------------------------------------------------
// convertToSarif
//-------------------------------------------------------------------
func convertToSarif(rawResult RawResult, tool_index, num int, result_file string) bool {

	//NUM_RULE := 13

	var sarif SARIF

	sarif.Schema = "https://json.schemastore.org/sarif-2.1.0.json"
	sarif.Version = "2.1.0"
	sarif.Runs = make([]Run, 1)

	setRuleInfo(&sarif, tool_index)

	sarif.Runs[0].Results = make([]Result, num)

	for i := 0; i < num; i++ {
		var result Result
		issue := rawResult.Issues[i]

		result.RuleID = "SWC-" + issue.SWC

		ruleIndex := getRuleIndex(result.RuleID, tool_index, sarif.Runs[0].Tool.ToolInfo.Rules)
		if ruleIndex == -1 {
			fmt.Printf("===> rule parsing failed\n")
			return false
		}

		result.Message.Text = "<br>- contract name : " + issue.Contract + "<br>- function name : " + issue.Function
		result.Locations = make([]Location, 1)
		result.Locations[0].PhysicalLocation.ArtifactLocation.Uri = strings.TrimPrefix(issue.FileName, "./")
		result.Locations[0].PhysicalLocation.Region.StartLine = issue.LineNo

		sarif.Runs[0].Results[i] = result
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		fmt.Printf("===> marshal failed : %s\n", err.Error())
		return false
	}
	//fmt.Println(string(data))

	sarif_file := strings.Replace(result_file, ".json", ".sarif", 1)
	err = ioutil.WriteFile(sarif_file, data, 0644)
	if err != nil {
		fmt.Printf("===> create sarif file failed : %s\n", err.Error())
		return false
	}

	fmt.Printf("===> sarif file created : %s\n", sarif_file)
	return true
}
*/
/*
//-------------------------------------------------------------------
// setRuleInfo
//-------------------------------------------------------------------
func setRuleInfo(sarif *SARIF, tool_index int) {

	num_rule := 0
	tool_name := ""

	if 0 == tool_index {
		num_rule  = 13
		tool_name = "Mythril"
	} else if 1 == tool_index {

	}

	sarif.Runs[0].Tool.ToolInfo.Name = tool_name
	sarif.Runs[0].Tool.ToolInfo.Rules = make([]Rule, num_rule)

	rules := sarif.Runs[0].Tool.ToolInfo.Rules

	var rule Rule

	rule.ID                          = "SWC-101"
        rule.ShortDescription.Text       = "Integer Arithmetic Bugs"
	rule.HelpInfo.Markdown           = ":warning: **Integer Arithmetic Bugs**<br><br>- It is possible to cause an integer overflow or underflow in the arithmetic operation.<br>:link: https://swcregistry.io/docs/SWC-101<br><br>:rocket: Prevent this by constraining inputs using the require() statement or use the OpenZeppelin SafeMath library for integer arithmetic operations. Refer to the transaction trace generated for this issue to reproduce the issue."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[0] = rule

	rule.ID                          = "SWC-104"
        rule.ShortDescription.Text       = "Unchecked return value from external call."
	rule.HelpInfo.Markdown           = ":warning: **Unchecked return value from external call.**<br><br>- The return value of a message call is not checked.<br>- External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller.<br>:link: https://swcregistry.io/docs/SWC-104<br><br>:rocket: The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[1] = rule

	rule.ID                          = "SWC-105"
        rule.ShortDescription.Text       = "Unprotected Ether Withdrawal"
	rule.HelpInfo.Markdown           = ":warning: **Unprotected Ether Withdrawal**<br><br>- Any sender can withdraw Ether from the contract account.<br>- Arbitrary senders other than the contract creator can profitably extract Ether from the contract account.<br>:link: https://swcregistry.io/docs/SWC-105<br><br>:rocket: Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[2] = rule

	rule.ID                          = "SWC-106"
        rule.ShortDescription.Text       = "Unprotected Selfdestruct"
	rule.HelpInfo.Markdown           = ":warning: **Unprotected Selfdestruct**<br><br>- Any sender can cause the contract to self-destruct.<br>- Any sender can trigger execution of the SELFDESTRUCT instruction to destroy this contract account and withdraw its balance to an arbitrary address.<br>:link: https://swcregistry.io/docs/SWC-106<br><br>:rocket: Review the transaction trace generated for this issue and make sure that appropriate security controls are in place to prevent unrestricted access."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[3] = rule

	rule.ID                          = "SWC-107"
        rule.ShortDescription.Text       = "External Call To User-Supplied Address"
	rule.HelpInfo.Markdown           = ":warning: **External Call To User-Supplied Address**<br><br>- A call to a user-supplied address is executed.<br>- An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour.<br>:link: https://swcregistry.io/docs/SWC-107<br><br>:rocket: Make sure that no state modifications are executed after this call and/or reentrancy guards are in place."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[4] = rule

	rule.ID                          = "SWC-110"
        rule.ShortDescription.Text       = "Exception State"
	rule.HelpInfo.Markdown           = ":warning: **Exception State**<br><br>- An assertion violation was triggered.<br>- It is possible to trigger an assertion violation. Note that Solidity assert() statements should only be used to check invariants.<br>:link: link: https://swcregistry.io/docs/SWC-110<br><br>:rocket: Review the transaction trace generated for this issue and either make sure your program logic is correct, or use require() instead of assert() if your goal is to constrain user inputs or enforce preconditions. Remember to validate inputs from both callers (for instance, via passed arguments) and callees (for instance, via return values)."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[5] = rule

	rule.ID                          = "SWC-112"
	rule.ShortDescription.Text       = "Delegatecall to a user-specified address"
	rule.HelpInfo.Markdown           = ":warning: **Delegatecall to a user-specified address**<br><br>- The contract delegates execution to another contract with a user-supplied address.<br>- The smart contract delegates execution to a user-supplied address.This could allow an attacker to execute arbitrary code in the context of this contract account and manipulate the state of the contract account or execute actions on its behalf.<br>:link: https://swcregistry.io/docs/SWC-112<br><br>:rocket: Check for invocations of delegatecall to a user-supplied address."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[6] = rule

	rule.ID                          = "SWC-113"
        rule.ShortDescription.Text       = "Multiple Calls in a Single Transaction"
	rule.HelpInfo.Markdown           = ":warning: **Multiple Calls in a Single Transaction**<br><br>- Multiple calls are executed in the same transaction.<br>- This call is executed following another call within the same transaction. It is possible that the call never gets executed if a prior call fails permanently. This might be caused intentionally by a malicious callee.<br>:link: https://swcregistry.io/docs/SWC-113<br><br>:rocket: If possible, refactor the code such that each transaction only executes one external call or make sure that all callees can be trusted (i.e. they’re part of your own codebase)."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[7] = rule

	rule.ID                          = "SWC-115"
	rule.ShortDescription.Text       = "Dependence on tx.origin"
	rule.HelpInfo.Markdown           = ":warning: **Dependence on tx.origin**<br><br>- Use of tx.origin as a part of authorization control.<br>- The tx.origin environment variable has been found to influence a control flow decision. Note that using tx.origin as a security control might cause a situation where a user inadvertently authorizes a smart contract to perform an action on their behalf. It is recommended to use msg.sender instead.<br>:link: https://swcregistry.io/docs/SWC-115<br><br>:rocket: Check whether control flow decisions are influenced by tx.origin."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[8] = rule

	rule.ID                          = "SWC-116"
	rule.ShortDescription.Text       = "Block values as a proxy for time"
	rule.HelpInfo.Markdown           = ":warning: **Dependence on predictable environment variable**<br><br>- Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Do nott use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.<br>:link: https://swcregistry.io/docs/SWC-116<br><br>:rocket: Check whether control flow decisions are influenced by block.coinbase,block.gaslimit, block.timestamp or block.number." 
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[9] = rule

	rule.ID                          = "SWC-120"
        rule.ShortDescription.Text       = "Weak Sources of Randomness from Chain Attributes"
        rule.HelpInfo.Markdown           = ":warning: **Dependence on predictable environment variable**<br><br>- Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Do nott use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.<br>:link: https://swcregistry.io/docs/SWC-120<br><br>:rocket: Check whether control flow decisions are influenced by block.coinbase,block.gaslimit, block.timestamp or block.number."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[10] = rule

	rule.ID                          = "SWC-124"
	rule.ShortDescription.Text       = "Write to an arbitrary storage location"
	rule.HelpInfo.Markdown           = ":warning: **Write to an arbitrary storage location**<br><br>- The caller can write to arbitrary storage locations.<br>- It is possible to write to arbitrary storage locations. By modifying the values of storage variables, attackers may bypass security controls or manipulate the business logic of the smart contract.<br>:link: https://swcregistry.io/docs/SWC-124<br><br>:rocket: As a general advice, given that all data structures share the same storage (address) space, one should make sure that writes to one data structure cannot inadvertently overwrite entries of another data structure."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[11] = rule

	rule.ID                          = "SWC-127"
	rule.ShortDescription.Text       = "Jump to an arbitrary instruction"
	rule.HelpInfo.Markdown           = ":warning: **Jump to an arbitrary instruction**<br><br>- The caller can redirect execution to arbitrary bytecode locations.<br>- It is possible to redirect the control flow to arbitrary locations in the code. This may allow an attacker to bypass security controls or manipulate the business logic of the smart contract.<br>:link: https://swcregistry.io/docs/SWC-127<br><br>:rocket: Avoid using low-level-operations and assembly to prevent this issue."
	rule.Properties.ProblemSeverity  = "warning"
	rule.Properties.SecuritySeverity = "8.0"
	rules[12] = rule
}
*/
/*
//-------------------------------------------------------------------
// getRuleIndex
//-------------------------------------------------------------------
func getRuleIndex(id string, tool_index int, rules []Rule) int {

	num := 0
	if 0 == tool_index {
		num = 13
	} else if 1 == tool_index {

	}

	for i := 0; i < num; i++ {
		if rules[i].ID == id {
			return i
		}
	}

	return -1
}
*/

