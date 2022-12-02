package common


//-------------------------------------------------------------------
// SARIF format
//-------------------------------------------------------------------
type SDesc struct {
        Text                    string          `json:"text"`
}

type FDesc struct {
        Text                    string          `json:"text"`
}

type Help struct {
        Text                    string          `json:"text"`
        Markdown                string          `json:"markdown"`       // markdown is available, it is displayed instead of help.text
}

type Property struct {
        ProblemSeverity         string          `json:"problem.severity"`       // error, warning, recommendation
        SecuritySeverity        string          `json:"security-severity"`      // critical : > 9.0, high : 7.0 ~ 8.9, medium : 4.0 ~ 6.9, low : <= 3.9
}

type Rule struct {
        ID                      string          `json:"id"`
        Name                    string          `json:"name"`
        ShortDescription        SDesc           `json:"shortDescription"`
        FullDescription         FDesc           `json:"fullDescription"`
        HelpInfo                Help            `json:"help"`
        Properties              Property        `json:"properties"`
}

type Driver struct {
        Name                    string          `json:"name"`
        Rules                   []Rule          `json:"rules"`
}

type Msg struct {
        Text                    string          `json:"text"`
}

type ALocation struct {
        Uri                     string          `json:"uri"`    // a file in the repository
}

type RegionInfo struct {
        StartLine               int             `json:"startLine"`
        //StartComuln           int             `json:"startColumn"`
        EndLine                 int             `json:"endLine"`
        //EndColumn             int             `json:"endColumn"`
}

type PLocation struct {
        ArtifactLocation        ALocation       `json:"artifactLocation"`
        Region                  RegionInfo      `json:"region"`
}

type Location struct {
        PhysicalLocation        PLocation       `json:"physicalLocation"`
}

type FingerPrint struct {
        PrimaryLocationLineHash string          `json:"primaryLocationLineHash"`
}

type Result struct {
        RuleID                  string          `json:"ruleId"`
        Message                 Msg             `json:"message"`
        Locations               []Location      `json:"locations"`      // maximum of 10
        //PartialFingerprints   FingerPrint     `json:"partialFingerprints"`
}

type Analyzer struct {
        ToolInfo                Driver          `json:"driver"`
}

type Run struct {
        Tool                    Analyzer        `json:"tool"`
        Results                 []Result        `json:"results"`        // maximum of 5000 results, 10 MB
}

type SARIF struct {
        Schema                  string          `json:"$schema"`
        Version                 string          `json:"version"`
        Runs                    []Run           `json:"runs"`
}


