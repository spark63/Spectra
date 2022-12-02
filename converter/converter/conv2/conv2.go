package conv2

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"strings"
	"conv/common"
)

const CONV = "conv2"


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

        var rawResult common.SARIF
        err = json.Unmarshal(data, &rawResult)
        if err != nil {
                fmt.Printf("===> (%s) file unmarshal failed : %s\n", CONV, err.Error())
                return false
        }
        //fmt.Printf("%+v\n", rawResult)

        len := len(rawResult.Runs[0].Results)
        if len == 0 {
                fmt.Printf("===> (%s) empty result\n", CONV)
                return false
        }

	len = getValidCount(rawResult, len)
	if len == 0 {
                fmt.Printf("===> (%s) empty valid result\n", CONV)
                return false
        }
	//fmt.Printf("===> (%s) valid result count : %d\n", CONV, len)

        return convertToSarif(rawResult, len, result_file)
}

//-------------------------------------------------------------------
// getValidCount
//-------------------------------------------------------------------
func getValidCount(results common.SARIF, num int) int {

	rules := results.Runs[0].Tool.ToolInfo.Rules
	num_rule := len(rules)
	valid := 0

	for i := 0; i < num; i++ {
		rule_id := results.Runs[0].Results[i].RuleID

		for j := 0; j < num_rule; j++ {
			if rules[j].ID == rule_id {
				if rules[j].Properties.SecuritySeverity != "0.0" {
					valid++
				}
				break
			}
		}
	}
	return valid
}


//-------------------------------------------------------------------
// getRuleId
//-------------------------------------------------------------------
func getRuleId(rawId string) string {

	i1 := strings.Index(rawId, "-")
	i2 := strings.Index(rawId[i1+1:], "-")

	return rawId[i2+i1+2:]
}


//-------------------------------------------------------------------
// convertToSarif
//-------------------------------------------------------------------
func convertToSarif(rawResult common.SARIF, num int, result_file string) bool {

        var sarif common.SARIF

        sarif.Schema = "https://json.schemastore.org/sarif-2.1.0.json"
        sarif.Version = "2.1.0"
        sarif.Runs = make([]common.Run, 1)

        setBaseRuleInfo(&sarif)

        sarif.Runs[0].Results = make([]common.Result, num)

        for i := 0; i < num; i++ {
                var result common.Result

		raw_result := rawResult.Runs[0].Results[i]
                result.RuleID = getRuleId(raw_result.RuleID)

                ruleIndex := getRuleIndex(result.RuleID, sarif.Runs[0].Tool.ToolInfo.Rules)
                if ruleIndex == -1 {
                        fmt.Printf("===> (%s) rule parsing failed\n", CONV)
                        return false
                }

		text := strings.ReplaceAll(raw_result.Message.Text, "\n", "<br>")
		text  = strings.ReplaceAll(text, "\t", "")
		result.Message.Text = "<br>- " + text
                result.Locations = make([]common.Location, 1)
                result.Locations[0].PhysicalLocation.ArtifactLocation.Uri = raw_result.Locations[0].PhysicalLocation.ArtifactLocation.Uri
                result.Locations[0].PhysicalLocation.Region.StartLine = raw_result.Locations[0].PhysicalLocation.Region.StartLine
		result.Locations[0].PhysicalLocation.Region.EndLine   = raw_result.Locations[0].PhysicalLocation.Region.EndLine
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
// getRuleIndex
//-------------------------------------------------------------------
func getRuleIndex(id string, rules []common.Rule) int {

        num := 56

        for i := 0; i < num; i++ {
                if rules[i].ID == id {
                        return i
                }
        }

        return -1
}


//-------------------------------------------------------------------
// setBaseRuleInfo
//-------------------------------------------------------------------
func setBaseRuleInfo(sarif *common.SARIF) {

        num_rule := 56
        tool_name := "Slither"

        sarif.Runs[0].Tool.ToolInfo.Name = tool_name
        sarif.Runs[0].Tool.ToolInfo.Rules = make([]common.Rule, num_rule)

        rules := sarif.Runs[0].Tool.ToolInfo.Rules

        var rule common.Rule

        rule.ID                          = "abiencoderv2-array"
        rule.ShortDescription.Text       = "Storage ABIEncoderV2 Array"
        rule.HelpInfo.Markdown           = ":warning: **Storage ABIEncoderV2 Array**<br><br>- solc versions 0.4.7-0.5.9 contain a compiler bug leading to incorrect ABI encoder usage.<br>:link: https://blog.ethereum.org/2019/06/25/solidity-storage-array-bugs/<br><br>:rocket: Use a compiler >= 0.5.10"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[0] = rule

        rule.ID                          = "array-by-reference"
        rule.ShortDescription.Text       = "Modifying storage array by value"
        rule.HelpInfo.Markdown           = ":warning: **Modifying storage array by value**<br><br>- Detect arrays passed to a function that expects reference to a storage array<br><br>:rocket: Ensure the correct usage of memory and storage in the function parameters. Make all the locations explicit."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[1] = rule

	rule.ID                          = "incorrect-shift"
        rule.ShortDescription.Text       = "Incorrect shift in assembly"
        rule.HelpInfo.Markdown           = ":warning: **Incorrect shift in assembly**<br><br>- Detect if the values in a shift operation are reversed<br><br>:rocket: Swap the order of parameters"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[2] = rule

	rule.ID                          = "multiple-constructors"
        rule.ShortDescription.Text       = "Multiple constructor scheme"
        rule.HelpInfo.Markdown           = ":warning: **Multiple constructor scheme**<br><br>- Detect multiple constructor definitions in the same contract (using new and old schemes)<br><br>:rocket: Only declare one constructor, preferably using the new scheme constructor(...) instead of function <contractName>(...)."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[3] = rule

        rule.ID                          = "name-reused"
        rule.ShortDescription.Text       = "Name reused"
        rule.HelpInfo.Markdown           = ":warning: **Name reused**<br><br>- If a codebase has two contracts the similar names, the compilation artifacts will not contain one of the contracts with the duplicate name.<br>- Bob's truffle codebase has two contracts named ERC20. When truffle compile runs, only one of the two contracts will generate artifacts in build/contracts. As a result, the second contract cannot be analyzed.<br><br>:rocket: Rename the contract."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[4] = rule

        rule.ID                          = "public-mappings-nested"
        rule.ShortDescription.Text       = "Public mappings with nested variables"
        rule.HelpInfo.Markdown           = ":warning: **Public mappings with nested variables**<br><br>- Prior to Solidity 0.5, a public mapping with nested structures returned incorrect values.<br>- Bob interacts with a contract that has a public mapping with nested structures. The values returned by the mapping are incorrect, breaking Bob's usage<br>:link: https://github.com/ethereum/solidity/issues/5520<br><br>:rocket: Do not use public mapping with nested structures."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[5] = rule

        rule.ID                          = "rtlo"
        rule.ShortDescription.Text       = "Right-to-Left-Override character"
        rule.HelpInfo.Markdown           = ":warning: **Right-to-Left-Override character**<br><br>- An attacker can manipulate the logic of the contract by using a right-to-left-override character (U+202E).<br><br>:rocket: Special control characters must not be allowed."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[6] = rule

        rule.ID                          = "shadowing-state"
        rule.ShortDescription.Text       = "State variable shadowing"
        rule.HelpInfo.Markdown           = ":warning: **State variable shadowing**<br><br>- Detection of state variables shadowed.<br><br>:rocket: Remove the state variable shadowing."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[7] = rule

        rule.ID                          = "suicidal"
        rule.ShortDescription.Text       = "Suicidal"
        rule.HelpInfo.Markdown           = ":warning: **Suicidal**<br><br>- Unprotected call to a function executing selfdestruct/suicide.<br><br>:rocket: Protect access to all sensitive functions."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[8] = rule

        rule.ID                          = "uninitialized-state"
        rule.ShortDescription.Text       = "Uninitialized state variables"
        rule.HelpInfo.Markdown           = ":warning: **Uninitialized state variables**<br><br>- Uninitialized state variables.<br><br>:rocket: Initialize all the variables. If a variable is meant to be initialized to zero, explicitly set it to zero to improve code readability."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[9] = rule

        rule.ID                          = "uninitialized-storage"
        rule.ShortDescription.Text       = "Uninitialized storage variables"
        rule.HelpInfo.Markdown           = ":warning: **Uninitialized storage variables**<br><br>- An uninitialized storage variable will act as a reference to the first state variable, and can override a critical variable.<br><br>:rocket: Initialize all storage variables."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[10] = rule

        rule.ID                          = "unprotected-upgrade"
        rule.ShortDescription.Text       = "Unprotected upgradeable contract"
        rule.HelpInfo.Markdown           = ":warning: **Unprotected upgradeable contract**<br><br>- Detects logic contract that can be destructed.<br><br>:rocket: Add a constructor to ensure initialize cannot be called on the logic contract."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[11] = rule

        rule.ID                          = "arbitrary-send"
        rule.ShortDescription.Text       = "Functions that send Ether to arbitrary destinations"
        rule.HelpInfo.Markdown           = ":warning: **Functions that send Ether to arbitrary destinations**<br><br>- Unprotected call to a function sending Ether to an arbitrary address.<br><br>:rocket: Ensure that an arbitrary user cannot withdraw unauthorized funds."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[12] = rule

        rule.ID                          = "controlled-array-length"
        rule.ShortDescription.Text       = "Array Length Assignment"
        rule.HelpInfo.Markdown           = ":warning: **Array Length Assignment**<br><br>- Detects the direct assignment of an array's length.<br><br>:rocket: Do not allow array lengths to be set directly set; instead, opt to add values as needed. Otherwise, thoroughly review the contract to ensure a user-controlled variable cannot reach an array length assignment."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[13] = rule

        rule.ID                          = "controlled-delegatecall"
        rule.ShortDescription.Text       = "Controlled Delegatecall"
        rule.HelpInfo.Markdown           = ":warning: **Controlled Delegatecall**<br><br>- Delegatecall or callcode to an address controlled by the user.<br><br>:rocket: Avoid using delegatecall. Use only trusted destinations."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[14] = rule

        rule.ID                          = "delegatecall-loop"
        rule.ShortDescription.Text       = "Payable functions using delegatecall inside a loop"
        rule.HelpInfo.Markdown           = ":warning: **Payable functions using delegatecall inside a loop**<br><br>- Detect the use of delegatecall inside a loop in a payable function.<br><br>:rocket: Carefully check that the function called by delegatecall is not payable/doesn't use msg.value."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[15] = rule

	rule.ID                          = "msg-value-loop"
        rule.ShortDescription.Text       = "msg.value inside a loop"
        rule.HelpInfo.Markdown           = ":warning: **msg.value inside a loop**<br><br>- Detect the use of msg.value inside a loop.<br><br>:rocket: Track msg.value through a local variable and decrease its amount on every iteration/usage."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[16] = rule

	rule.ID                          = "reentrancy-eth"
        rule.ShortDescription.Text       = "Reentrancy vulnerabilities"
        rule.HelpInfo.Markdown           = ":warning: **Reentrancy vulnerabilities**<br><br>- Detection of the reentrancy bug.<br>:link: https://docs.soliditylang.org/en/v0.4.21/security-considerations.html#re-entrancy<br><br>:rocket: Apply the check-effects-interactions pattern."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[17] = rule

	rule.ID                          = "storage-array"
        rule.ShortDescription.Text       = "Storage Signed Integer Array"
        rule.HelpInfo.Markdown           = ":warning: **Storage Signed Integer Array**<br><br>- solc versions 0.4.7-0.5.10 contain a compiler bug leading to incorrect values in signed integer arrays.<br>:link: https://blog.ethereum.org/2019/06/25/solidity-storage-array-bugs/<br><br>:rocket: Use a compiler version >= 0.5.10."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[18] = rule

	rule.ID                          = "unchecked-transfer"
        rule.ShortDescription.Text       = "Unchecked transfer"
        rule.HelpInfo.Markdown           = ":warning: **Unchecked transfer**<br><br>- The return value of an external transfer/transferFrom call is not checked<br><br>:rocket: Use SafeERC20, or ensure that the transfer/transferFrom return value is checked."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[19] = rule

	rule.ID                          = "weak-prng"
        rule.ShortDescription.Text       = "Weak PRNG"
        rule.HelpInfo.Markdown           = ":warning: **Weak PRNG**<br><br>- Weak PRNG due to a modulo on block.timestamp, now or blockhash.<br>- These can be influenced by miners to some extent so they should be avoided.<br><br>:rocket: Do not use `block.timestamp`, `now` or `blockhash` as a source of randomness"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[20] = rule

	rule.ID                          = "enum-conversion"
        rule.ShortDescription.Text       = "Dangerous enum conversion"
        rule.HelpInfo.Markdown           = ":warning: **Dangerous enum conversion**<br><br>- Detect out-of-range enum conversion (solc < 0.4.5).<br><br>:rocket: Use a recent compiler version. If solc <0.4.5 is required, check the enum conversion range."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[21] = rule

	rule.ID                          = "erc20-interface"
        rule.ShortDescription.Text       = "Incorrect erc20 interface"
        rule.HelpInfo.Markdown           = ":warning: **Incorrect erc20 interface**<br><br>- Incorrect return values for ERC20 functions.<br>- A contract compiled with Solidity > 0.4.22 interacting with these functions will fail to execute them, as the return value is missing.<br><br>:rocket: Set the appropriate return values and types for the defined ERC20 functions."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[22] = rule

	rule.ID                          = "erc721-interface"
        rule.ShortDescription.Text       = "Incorrect erc721 interface"
        rule.HelpInfo.Markdown           = ":warning: **Incorrect erc721 interface**<br><br>- Incorrect return values for ERC721 functions.<br>- A contract compiled with solidity > 0.4.22 interacting with these functions will fail to execute them, as the return value is missing.<br><br>:rocket: Set the appropriate return values and vtypes for the defined ERC721 functions."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[23] = rule

	rule.ID                          = "incorrect-equality"
        rule.ShortDescription.Text       = "Dangerous strict equalities"
        rule.HelpInfo.Markdown           = ":warning: **Dangerous strict equalities**<br><br>- Use of strict equalities that can be easily manipulated by an attacker.<br><br>:rocket: Don't use strict equality to determine if an account has enough Ether or tokens."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[24] = rule

	rule.ID                          = "locked-ether"
        rule.ShortDescription.Text       = "Contracts that lock Ether"
        rule.HelpInfo.Markdown           = ":warning: **Contracts that lock Ether**<br><br>- Contract with a payable function, but without a withdrawal capacity.<br><br>:rocket: Remove the payable attribute or add a withdraw function."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[25] = rule

	rule.ID                          = "mapping-deletion"
        rule.ShortDescription.Text       = "Deletion on mapping containing a structure"
        rule.HelpInfo.Markdown           = ":warning: **Deletion on mapping containing a structure**<br><br>- A deletion in a structure containing a mapping will not delete the mapping.<br>- The remaining data may be used to compromise the contract.<br>:link: https://docs.soliditylang.org/en/latest/types.html##delete<br><br>:rocket: Use a lock mechanism instead of a deletion to disable structure containing a mapping."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[26] = rule

	rule.ID                          = "shadowing-abstract"
        rule.ShortDescription.Text       = "State variable shadowing from abstract contracts"
        rule.HelpInfo.Markdown           = ":warning: **State variable shadowing from abstract contracts**<br><br>- Detection of state variables shadowed from abstract contracts.<br><br>:rocket: Remove the state variable shadowing."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[27] = rule

	rule.ID                          = "tautology"
        rule.ShortDescription.Text       = "Tautology or contradiction"
        rule.HelpInfo.Markdown           = ":warning: **Tautology or contradiction**<br><br>- Detects expressions that are tautologies or contradictions.<br><br>:rocket: Fix the incorrect comparison by changing the value type or the comparison."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[28] = rule

	rule.ID                          = "write-after-write"
        rule.ShortDescription.Text       = "Write after write"
        rule.HelpInfo.Markdown           = ":warning: **Write after write**<br><br>- Detects variables that are written but never read and written again.<br><br>:rocket: Fix or remove the writes."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[29] = rule

	rule.ID                          = "boolean-cst"
        rule.ShortDescription.Text       = "Misuse of a Boolean constant"
        rule.HelpInfo.Markdown           = ":warning: **Misuse of a Boolean constant**<br><br>- Detects the misuse of a Boolean constant.<br><br>:rocket: Verify and simplify the condition."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[30] = rule

	rule.ID                          = "constant-function-asm"
        rule.ShortDescription.Text       = "Constant functions using assembly code"
        rule.HelpInfo.Markdown           = ":warning: **Constant functions using assembly code**<br><br>- Functions declared as constant/pure/view using assembly code.<br>- constant/pure/view was not enforced prior to Solidity 0.5. Starting from Solidity 0.5, a call to a constant/pure/view function uses the STATICCALL opcode, which reverts in case of state modification.<br>- As a result, a call to an incorrectly labeled function may trap a contract compiled with Solidity 0.5.<br>:link: https://docs.soliditylang.org/en/develop/050-breaking-changes.html#interoperability-with-older-contracts<br><br>:rocket: Ensure the attributes of contracts compiled prior to Solidity 0.5.0 are correct."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[31] = rule

	rule.ID                          = "constant-function-state"
        rule.ShortDescription.Text       = "Constant functions changing the state"
        rule.HelpInfo.Markdown           = ":warning: **Constant functions changing the state**<br><br>- Functions declared as constant/pure/view change the state.<br>- constant/pure/view was not enforced prior to Solidity 0.5. Starting from Solidity 0.5, a call to a constant/pure/view function uses the STATICCALL opcode, which reverts in case of state modification.<br>- As a result, a call to an incorrectly labeled function may trap a contract compiled with Solidity 0.5.<br>:link: https://docs.soliditylang.org/en/develop/050-breaking-changes.html#interoperability-with-older-contracts<br><br>:rocket: Ensure that attributes of contracts compiled prior to Solidity 0.5.0 are correct."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[32] = rule

	rule.ID                          = "divide-before-multiply"
        rule.ShortDescription.Text       = "Divide before multiply"
        rule.HelpInfo.Markdown           = ":warning: **Divide before multiply**<br><br>- Solidity integer division might truncate. As a result, performing multiplication before division can sometimes avoid loss of precision.<br><br>:rocket: Consider ordering multiplication before division."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[33] = rule

	rule.ID                          = "reentrancy-no-eth"
        rule.ShortDescription.Text       = "Reentrancy vulnerabilities"
        rule.HelpInfo.Markdown           = ":warning: **Reentrancy vulnerabilities**<br><br>- Detection of the reentrancy bug.<br>:link: https://docs.soliditylang.org/en/v0.4.21/security-considerations.html#re-entrancy<br><br>:rocket: Apply the check-effects-interactions pattern."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[34] = rule

	rule.ID                          = "reused-constructor"
        rule.ShortDescription.Text       = "Reused base constructors"
        rule.HelpInfo.Markdown           = ":warning: **Reused base constructors**<br><br>- Detects if the same base constructor is called with arguments from two different locations in the same inheritance hierarchy.<br><br>:rocket: Remove the duplicate constructor call."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[35] = rule

	rule.ID                          = "tx-origin"
        rule.ShortDescription.Text       = "Dangerous usage of tx.origin"
        rule.HelpInfo.Markdown           = ":warning: **Dangerous usage of tx.origin**<br><br>- tx.origin-based protection can be abused by a malicious contract if a legitimate user interacts with the malicious contract.<br><br>:rocket: Do not use tx.origin for authorization."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[36] = rule

	rule.ID                          = "unchecked-lowlevel"
        rule.ShortDescription.Text       = "Unchecked low-level calls"
        rule.HelpInfo.Markdown           = ":warning: **Unchecked low-level calls**<br><br>- The return value of a low-level call is not checked.<br><br>:rocket: Ensure that the return value of a low-level call is checked or logged."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[37] = rule

	rule.ID                          = "unchecked-send"
        rule.ShortDescription.Text       = "Unchecked Send"
        rule.HelpInfo.Markdown           = ":warning: **Unchecked Send**<br><br>- The return value of a send is not checked.<br><br>:rocket: Ensure that the return value of send is checked or logged."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[38] = rule

	rule.ID                          = "uninitialized-local"
        rule.ShortDescription.Text       = "Uninitialized local variables"
        rule.HelpInfo.Markdown           = ":warning: **Uninitialized local variables**<br><br>- Uninitialized local variables.<br><br>:rocket: Initialize all the variables. If a variable is meant to be initialized to zero, explicitly set it to zero to improve code readability."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[39] = rule

	rule.ID                          = "unused-return"
        rule.ShortDescription.Text       = "Unused return"
        rule.HelpInfo.Markdown           = ":warning: **Unused return**<br><br>- The return value of an external call is not stored in a local or state variable.<br><br>:rocket: Ensure that all the return values of the function calls are used."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[40] = rule

	rule.ID                          = "incorrect-modifier"
        rule.ShortDescription.Text       = "Incorrect modifier"
        rule.HelpInfo.Markdown           = ":warning: **Incorrect modifier**<br><br>- If a modifier does not execute _ or revert, the execution of the function will return the default value, which can be misleading for the caller.<br><br>:rocket: All the paths in a modifier must execute _ or revert."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[41] = rule

	rule.ID                          = "shadowing-builtin"
        rule.ShortDescription.Text       = "Builtin Symbol Shadowing"
        rule.HelpInfo.Markdown           = ":warning: **Builtin Symbol Shadowing**<br><br>- Detection of shadowing built-in symbols using local variables, state variables, functions, modifiers, or events.<br><br>:rocket: Rename the local variables, state variables, functions, modifiers, and events that shadow a builtin symbol."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[42] = rule

	rule.ID                          = "shadowing-local"
        rule.ShortDescription.Text       = "Local variable shadowing"
        rule.HelpInfo.Markdown           = ":warning: **Local variable shadowing**<br><br>- Detection of shadowing using local variables.<br><br>:rocket: Rename the local variables that shadow another component."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[43] = rule

	rule.ID                          = "uninitialized-fptr-cst"
        rule.ShortDescription.Text       = "Uninitialized function pointers in constructors"
        rule.HelpInfo.Markdown           = ":warning: **Uninitialized function pointers in constructors**<br><br>- solc versions 0.4.5-0.4.26 and 0.5.0-0.5.8 contain a compiler bug leading to unexpected behavior when calling uninitialized function pointers in constructors.<br><br>:rocket: Initialize function pointers before calling. Avoid function pointers if possible."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[44] = rule

	rule.ID                          = "variable-scope"
        rule.ShortDescription.Text       = "Pre-declaration usage of local variables"
        rule.HelpInfo.Markdown           = ":warning: **Pre-declaration usage of local variables**<br><br>- Detects the possible usage of a variable before the declaration is stepped over (either because it is later declared, or declared in another scope).<br><br>:rocket: Move all variable declarations prior to any usage of the variable, and ensure that reaching a variable declaration does not depend on some conditional if it is used unconditionally."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[45] = rule

	rule.ID                          = "void-cst"
        rule.ShortDescription.Text       = "Void constructor"
        rule.HelpInfo.Markdown           = ":warning: **Void constructor**<br><br>- Detect the call to a constructor that is not implemented<br>:link: <br><br>:rocket: Remove the constructor call."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[46] = rule

	rule.ID                          = "calls-loop"
        rule.ShortDescription.Text       = "Calls inside a loop"
        rule.HelpInfo.Markdown           = ":warning: **Calls inside a loop**<br><br>- Calls inside a loop might lead to a denial-of-service attack.<br>:link: https://github.com/ethereum/wiki/wiki/Safety#favor-pull-over-push-for-external-calls<br><br>:rocket: Favor pull over push strategy for external calls."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[47] = rule

	rule.ID                          = "events-access"
        rule.ShortDescription.Text       = "Missing events access control"
        rule.HelpInfo.Markdown           = ":warning: **Missing events access control**<br><br>- Detect missing events for critical access control parameters<br><br>:rocket: Emit an event for critical parameter changes."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[48] = rule

	rule.ID                          = "events-maths"
        rule.ShortDescription.Text       = "Missing events arithmetic"
        rule.HelpInfo.Markdown           = ":warning: **Missing events arithmetic**<br><br>- Detect missing events for critical arithmetic parameters.<br><br>:rocket: Emit an event for critical parameter changes."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[49] = rule

	rule.ID                          = "incorrect-unary"
        rule.ShortDescription.Text       = "Dangerous unary expressions"
        rule.HelpInfo.Markdown           = ":warning: **Dangerous unary expressions**<br><br>- Unary expressions such as x=+1 probably typos.<br><br>:rocket: Remove the unary expression."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[50] = rule

	rule.ID                          = "missing-zero-check"
        rule.ShortDescription.Text       = "Missing zero address validation"
        rule.HelpInfo.Markdown           = ":warning: **Missing zero address validation**<br><br>- Detect missing zero address validation.<br><br>:rocket: Check that the address is not zero."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[51] = rule

	rule.ID                          = "reentrancy-benign"
        rule.ShortDescription.Text       = "Reentrancy vulnerabilities"
        rule.HelpInfo.Markdown           = ":warning: **Reentrancy vulnerabilities**<br><br>- Detection of the reentrancy bug.<br>:link: https://docs.soliditylang.org/en/v0.4.21/security-considerations.html#re-entrancy<br><br>:rocket: Apply the check-effects-interactions pattern."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[52] = rule

	rule.ID                          = "reentrancy-events"
        rule.ShortDescription.Text       = "Reentrancy vulnerabilities"
        rule.HelpInfo.Markdown           = ":warning: **Reentrancy vulnerabilities**<br><br>- Detection of the reentrancy bug.<br>:link: https://docs.soliditylang.org/en/v0.4.21/security-considerations.html#re-entrancy<br><br>:rocket: Apply the check-effects-interactions pattern."
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[53] = rule

	rule.ID                          = "timestamp"
        rule.ShortDescription.Text       = "Block timestamp"
        rule.HelpInfo.Markdown           = ":warning: **Block timestamp**<br><br>- Dangerous usage of block.timestamp. block.timestamp can be manipulated by miners.<br>- Bob's contract relies on block.timestamp for its randomness. Eve is a miner and manipulates block.timestamp to exploit Bob's contract.<br><br>:rocket: Avoid relying on block.timestamp"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[54] = rule

	rule.ID                          = "protected-vars"
        rule.ShortDescription.Text       = "Protected Variables"
        rule.HelpInfo.Markdown           = ":warning: **Protected Variables**<br><br>- Detect unprotected variable that are marked protected<br><br>:rocket: Add access controls to the vulnerable function"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[55] = rule
}



