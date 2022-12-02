package conv3

import (
	"fmt"
        "encoding/json"
        "io/ioutil"
        "strings"
        "conv/common"
)

const CONV = "conv3"

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

        //fmt.Printf("===> (%s) valid result count : %d\n", CONV, len)

        return convertToSarif(rawResult, len, result_file)
}


//-------------------------------------------------------------------
// getRuleId
//-------------------------------------------------------------------
func getRuleId(rawId string) string {

	return strings.TrimPrefix(rawId, "rules.")
}


//-------------------------------------------------------------------
// getRuleIndex
//-------------------------------------------------------------------
func getRuleIndex(id string, rules []common.Rule) int {

        num := 22

        for i := 0; i < num; i++ {
                if rules[i].ID == id {
                        return i
                }
        }

        return -1
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

                result.Message.Text = "<br>- " + raw_result.Message.Text
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
// setBaseRuleInfo
//-------------------------------------------------------------------
func setBaseRuleInfo(sarif *common.SARIF) {

        num_rule := 22
        tool_name := "Semgrep"

        sarif.Runs[0].Tool.ToolInfo.Name = tool_name
        sarif.Runs[0].Tool.ToolInfo.Rules = make([]common.Rule, num_rule)

        rules := sarif.Runs[0].Tool.ToolInfo.Rules

        var rule common.Rule

        rule.ID                          = "arbitrary-low-level-call"
        rule.ShortDescription.Text       = "arbitrary low level call"
	rule.HelpInfo.Markdown           = ":warning: **arbitray low level call**<br><br>- An attacker may perform call() to an arbitrary address with controlled calldata<br>:link: https://blocksecteam.medium.com/li-fi-attack-a-cross-chain-bridge-vulnerability-no-its-due-to-unchecked-external-call-c31e7dadf60f"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[0] = rule

	rule.ID                          = "basic-arithmetic-underflow"
	rule.ShortDescription.Text       = "basic arithmetic underflow"
	rule.HelpInfo.Markdown           = ":warning: **basic arithmetic underflow**<br><br>- Possible arithmetic underflow<br>:link: https://medium.com/@Knownsec_Blockchain_Lab/knownsec-blockchain-lab-umbnetwork-attack-event-analysis-9bae1141e58"
	rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[1] = rule

        rule.ID                          = "basic-oracle-manipulation"
        rule.ShortDescription.Text       = "basic oracle manipulation"
	rule.HelpInfo.Markdown           = ":warning: **basic oracle manipulation**<br><br>- Price oracle can be manipulated via flashloan<br>:link: https://medium.com/oneringfinance/onering-finance-exploit-post-mortem-after-oshare-hack-602a529db99b<br>:link: https://pwned-no-more.notion.site/The-Deus-Hack-Explained-647bf97afa2b4e4e9e8b882e68a75c0b"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "3.0"
        rules[2] = rule

        rule.ID                          = "basic-reentrancy"
        rule.ShortDescription.Text       = "basic reentrancy"
	rule.HelpInfo.Markdown           = ":warning: **basic reentrancy**<br><br>- A method is called on a user supplied argument<br>:link: https://web.archive.org/web/20220208112938/https://earnhub.medium.com/b9d39169655f"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[3] = rule

        rule.ID                          = "compound-borrowfresh-reentrancy"
        rule.ShortDescription.Text       = "compound borrowfresh reentrancy"
	rule.HelpInfo.Markdown           = ":warning: **compound borrowfresh reentrancy**<br><br>- Function borrowFresh() in Compound performs state update after doTransferOut()<br>:link: https://slowmist.medium.com/another-day-another-reentrancy-attack-5cde10bbb2b4"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[4] = rule

        rule.ID                          = "compound-sweeptoken-not-restricted"
        rule.ShortDescription.Text       = "compound seeeptoken not restricted"
	rule.HelpInfo.Markdown           = ":warning: **compound sweeptoken not restricted**<br><br>- function sweepToken is allowed to be called by anyone<br>:link: https://chainsecurity.com/security-audit/compound-ctoken/<br>:link: https://blog.openzeppelin.com/compound-comprehensive-protocol-audit/"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[5] = rule

        rule.ID                          = "erc20-public-burn"
        rule.ShortDescription.Text       = "erc20 poublic burn"
	rule.HelpInfo.Markdown           = ":warning: **erc20 public burn**<br><br>- Anyone can burn tokens of other accounts<br>:link: https://twitter.com/danielvf/status/1511013322015051797"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[6] = rule

        rule.ID                          = "erc20-public-transfer"
        rule.ShortDescription.Text       = "erc20 public transfer"
	rule.HelpInfo.Markdown           = ":warning: **erc20 public transfer**<br><br>- Custom ERC20 implementation exposes _transfer() as public<br>:link: https://medium.com/@Knownsec_Blockchain_Lab/creat-future-was-tragically-transferred-coins-at-will-who-is-the-mastermind-behind-the-scenes-8ad42a7af814"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[7] = rule

        rule.ID                          = "erc677-reentrancy"
        rule.ShortDescription.Text       = "erc677 reentrancy"
	rule.HelpInfo.Markdown           = ":warning: **erc677 reentrancy**<br><br>- ERC677 callAfterTransfer() reentrancy<br>:link: https://twitter.com/peckshield/status/1509431646818234369"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[8] = rule

        rule.ID                          = "erc721-arbitrary-transferfrom"
        rule.ShortDescription.Text       = "erc721 arbitrary transferfrom"
	rule.HelpInfo.Markdown           = ":warning: **erc721 arbitrary transferfrom**<br><br>- Custom ERC721 implementation lacks access control checks in _transfer()<br>:link: https://twitter.com/BlockSecAlert/status/1516289618605654024"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[9] = rule

        rule.ID                          = "erc721-reentrancy"
        rule.ShortDescription.Text       = "erc721 reentrancy"
	rule.HelpInfo.Markdown           = ":warning: **erc721 reentrancy**<br><br>- ERC721 onERC721Received() reentrancy<br>:link: https://blocksecteam.medium.com/when-safemint-becomes-unsafe-lessons-from-the-hypebears-security-incident-2965209bda2a"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[10] = rule

        rule.ID                          = "erc777-reentrancy"
        rule.ShortDescription.Text       = "erc777 reentrancy"
	rule.HelpInfo.Markdown           = ":warning: **erc777 reentrancy**<br><br>- ERC777 tokensReceived() reentrancy"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[11] = rule

        rule.ID                          = "gearbox-tokens-path-confusion"
        rule.ShortDescription.Text       = "gearbox tokens path confusion"
	rule.HelpInfo.Markdown           = ":warning: **gearbox tokens path confusion**<br><br>- UniswapV3 adapter implemented incorrect extraction of path parameters<br>:link: https://medium.com/@nnez/different-parsers-different-results-acecf84dfb0c"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[12] = rule

        rule.ID                          = "keeper-network-oracle-manipulation"
        rule.ShortDescription.Text       = "keeper network oracle manipulation"
	rule.HelpInfo.Markdown           = ":warning: **keeper-network-oracle-manipulation**<br><br>- Keep3rV2.current() call has high data freshness, but it has low security, an exploiter simply needs to manipulate 2 data points to be able to impact the feed.<br>:link: https://andrecronje.medium.com/keep3r-network-on-chain-oracle-price-feeds-3c67ed002a9"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[13] = rule

        rule.ID                          = "oracle-price-update-not-restricted"
        rule.ShortDescription.Text       = "oracle price update not restricted"
	rule.HelpInfo.Markdown           = ":warning: **oracle price update not restricted**<br><br>- Oracle price data can be submitted by anyone<br>:link: https://medium.com/@hacxyk/aave-v3s-price-oracle-manipulation-vulnerability-168e44e9e374"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[14] = rule

        rule.ID                          = "redacted-cartel-custom-approval-bug"
        rule.ShortDescription.Text       = "redacted cartel custom approval bug"
	rule.HelpInfo.Markdown           = ":warning: **redacted cartel custom approval bug**<br><br>- transferFrom() can steal allowance of other accounts<br>:link: https://medium.com/immunefi/redacted-cartel-custom-approval-logic-bugfix-review-9b2d039ca2c5"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[15] = rule

        rule.ID                          = "rigoblock-missing-access-control"
        rule.ShortDescription.Text       = "rigoblock missing access control"
	rule.HelpInfo.Markdown           = ":warning: **rigoblock missing access contro**<br><br>- setMultipleAllowances() is missing onlyOwner modifier<br>:link: https://twitter.com/danielvf/status/1494317265835147272"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[16] = rule

        rule.ID                          = "rikkei-setoracledata-not-restricted"
        rule.ShortDescription.Text       = "rikkei setoracledata not restricted"
	rule.HelpInfo.Markdown           = ":warning: **rikkei setoracledata not restricted**<br><br>- Function setOracleData is allowed to be called by anyone<br>:link: https://twitter.com/BlockSecTeam/status/1514815673800663045"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[17] = rule

        rule.ID                          = "sense-missing-oracle-access-control"
        rule.ShortDescription.Text       = "sense missing oracle access control"
	rule.HelpInfo.Markdown           = ":warning: **sense missing oracle access control**<br><br>- Oracle update is not restricted in $F()<br>:link: https://medium.com/immunefi/sense-finance-access-control-issue-bugfix-review-32e0c806b1a0"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[18] = rule

        rule.ID                          = "superfluid-ctx-injection"
        rule.ShortDescription.Text       = "superfluid ctx injection"
	rule.HelpInfo.Markdown           = ":warning: **superfluid ctx injection**<br><br>- A specially crafted calldata may be used to impersonate other accounts<br>:link: https://rekt.news/superfluid-rekt/<br>:link: https://medium.com/superfluid-blog/08-02-22-exploit-post-mortem-15ff9c97cdd"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[19] = rule

        rule.ID                          = "tecra-coin-burnfrom-bug"
        rule.ShortDescription.Text       = "tecra coin burnfrom bug"
	rule.HelpInfo.Markdown           = ":warning: **tecra coin burnfrom bug**<br><br>- Parameter [from] is checked at incorrect position in [_allowances] mapping<br>:link: https://twitter.com/Mauricio_0218/status/1490082073096462340"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "8.0"
        rules[20] = rule

        rule.ID                          = "treasuredao-input-validation-vuln"
        rule.ShortDescription.Text       = "treasuredao input validation vuln"
	rule.HelpInfo.Markdown           = ":warning: **treasuredao input validation vuln**<br><br>- A user supplied argument can be passed as zero to multiplication operation<br>:link: https://slowmist.medium.com/analysis-of-the-treasuredao-zero-fee-exploit-73791f4b9c14"
        rule.Properties.ProblemSeverity  = "warning"
        rule.Properties.SecuritySeverity = "5.0"
        rules[21] = rule
}



