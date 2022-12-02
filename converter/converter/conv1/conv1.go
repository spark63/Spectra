package conv1

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"strings"
	"conv/common"
)

const CONV = "conv1"

//-------------------------------------------------------------------
// Mythril's result
//-------------------------------------------------------------------
type Issue struct {
        Code            string  `json:"code"`
        Contract        string  `json:"contract"`
        Description     string  `json:"description"`
        FileName        string  `json:"filename"`
        Function        string  `json:"function"`
        LineNo          int     `json:"lineno"`
        Severity        string  `json:"severity"`
        SWC             string  `json:"swc-id"`
        Title           string  `json:"title"`
}

type RawResult struct {
        Error           string	`json:"error"`
        Issues          []Issue `json:"issues"`
        Success         bool	`json:"success"`
}


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


//-------------------------------------------------------------------
// DoCreate
//-------------------------------------------------------------------
func DoCreate(result_file string) bool {

        data, err := ioutil.ReadFile(result_file)
        if err != nil {
                fmt.Printf("===> (%s) file read error : %s\n", CONV, result_file)
                return false
        }

        //data_string := string(data)
        //fmt.Println(data_string)

        var rawResult RawResult
        err = json.Unmarshal(data, &rawResult)
        if err != nil {
                fmt.Printf("===> (%s) file unmarshal failed : %s\n", CONV, err.Error())
                return false
        }
        //fmt.Printf("%+v\n", rawResult)

        if rawResult.Success != true {
                fmt.Printf("===> (%s) analysys failed : %s\n", CONV, rawResult.Error)
                return false
        }

        if rawResult.Error != "" {
                fmt.Printf("===> (%s) failed result\n", CONV)
                return false
        }

        len := len(rawResult.Issues)
        if len == 0 {
                fmt.Printf("===> (%s) empty result\n", CONV)
                return false
        }

        //showResult(rawResult)

        return convertToSarif(rawResult, len, result_file)
}


//-------------------------------------------------------------------
// convertToSarif
//-------------------------------------------------------------------
func convertToSarif(rawResult RawResult, num int, result_file string) bool {

        //NUM_RULE := 13

        var sarif common.SARIF

        sarif.Schema = "https://json.schemastore.org/sarif-2.1.0.json"
        sarif.Version = "2.1.0"
        sarif.Runs = make([]common.Run, 1)

        setRuleInfo(&sarif)

        sarif.Runs[0].Results = make([]common.Result, num)

        for i := 0; i < num; i++ {
                var result common.Result
                issue := rawResult.Issues[i]

                result.RuleID = "SWC-" + issue.SWC

                ruleIndex := getRuleIndex(result.RuleID, sarif.Runs[0].Tool.ToolInfo.Rules)
                if ruleIndex == -1 {
                        fmt.Printf("===> (%s) rule parsing failed\n", CONV)
                        return false
                }

                result.Message.Text = "<br>- contract name : " + issue.Contract + "<br>- function name : " + issue.Function
                result.Locations = make([]common.Location, 1)
                result.Locations[0].PhysicalLocation.ArtifactLocation.Uri = strings.TrimPrefix(issue.FileName, "./")
                result.Locations[0].PhysicalLocation.Region.StartLine = issue.LineNo
		result.Locations[0].PhysicalLocation.Region.EndLine   = issue.LineNo
                sarif.Runs[0].Results[i] = result
        }

        data, err := json.MarshalIndent(sarif, "", "  ")
        if err != nil {
                fmt.Printf("===> (%s) marshal failed : %s\n", CONV, err.Error())
                return false
        }
        //fmt.Println(string(data))

        sarif_file := strings.Replace(result_file, ".json", ".sarif", 1)
        err = ioutil.WriteFile(sarif_file, data, 0644)
        if err != nil {
                fmt.Printf("===> (%s) create sarif file failed : %s\n", CONV, err.Error())
                return false
        }

        fmt.Printf("===> (%s) sarif file created : %s\n", CONV, sarif_file)
        return true
}


//-------------------------------------------------------------------
// setRuleInfo
//-------------------------------------------------------------------
func setRuleInfo(sarif *common.SARIF) {

        num_rule := 13
        tool_name := "Mythril"

        sarif.Runs[0].Tool.ToolInfo.Name = tool_name
        sarif.Runs[0].Tool.ToolInfo.Rules = make([]common.Rule, num_rule)

        rules := sarif.Runs[0].Tool.ToolInfo.Rules

        var rule common.Rule

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


//-------------------------------------------------------------------
// getRuleIndex
//-------------------------------------------------------------------
func getRuleIndex(id string, rules []common.Rule) int {

        num := 13

        for i := 0; i < num; i++ {
                if rules[i].ID == id {
                        return i
                }
        }

        return -1
}


