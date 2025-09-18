window.scanData = {
  "scanDate": "2025-09-19T02:29:11.081322+09:00",
  "totalServers": 100,
  "servers": [
    {
      "name": "n8n",
      "owner": "n8n-io",
      "fullName": "n8n-io/n8n",
      "url": "https://github.com/n8n-io/n8n",
      "stars": 138868,
      "description": "Fair-code workflow automation platform with native AI capabilities. Combine visual building with custom code, self-host or cloud, 400+ integrations.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:38:42Z",
      "scanDate": "2025-09-19T02:12:29.071339+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 1,
          "low": 6,
          "medium": 0,
          "total": 12,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-xffm-g5w8-qvg7",
              "pkg": "@eslint/plugin-kit",
              "severity": "LOW",
              "title": "@eslint/plugin-kit is vulnerable to Regular Expression Denial of Service attacks through ConfigCommentParser"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-xffm-g5w8-qvg7",
              "pkg": "@eslint/plugin-kit",
              "severity": "LOW",
              "title": "@eslint/plugin-kit is vulnerable to Regular Expression Denial of Service attacks through ConfigCommentParser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-26791",
              "pkg": "dompurify",
              "severity": "MODERATE",
              "title": "DOMPurify allows Cross-site Scripting (XSS)"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57665",
              "pkg": "element-plus",
              "severity": "MODERATE",
              "title": "Element Plus Link component (el-link) implements insufficient input validation for the href attribute"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-37620",
              "pkg": "html-minifier",
              "severity": "HIGH",
              "title": "kangax html-minifier REDoS vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53382",
              "pkg": "prismjs",
              "severity": "MODERATE",
              "title": "PrismJS DOM Clobbering vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57753",
              "pkg": "vite-plugin-static-copy",
              "severity": "MODERATE",
              "title": "vite-plugin-static-copy files not included in `src` are possible to access with a crafted request"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-26115",
              "pkg": "word-wrap",
              "severity": "MODERATE",
              "title": "word-wrap vulnerable to Regular Expression Denial of Service"
            }
          ]
        },
        "outdated": {
          "count": 0,
          "packages": {}
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": true,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 89,
      "errors": []
    },
    {
      "name": "context7",
      "owner": "upstash",
      "fullName": "upstash/context7",
      "url": "https://github.com/upstash/context7",
      "stars": 30689,
      "description": "Context7 MCP Server -- Up-to-date code documentation for LLMs and AI code editors",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T17:06:32Z",
      "scanDate": "2025-09-19T02:13:18.273021+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "outdated": {
          "count": 4,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "context7",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "commander": {
              "dependent": "context7",
              "latest": "14.0.1",
              "wanted": "14.0.1"
            },
            "undici": {
              "dependent": "context7",
              "latest": "7.16.0",
              "wanted": "6.21.3"
            },
            "zod": {
              "dependent": "context7",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "gpt-researcher",
      "owner": "assafelovic",
      "fullName": "assafelovic/gpt-researcher",
      "url": "https://github.com/assafelovic/gpt-researcher",
      "stars": 23509,
      "description": "LLM based autonomous agent that conducts deep local and web research on any topic and generates a long report with citations.",
      "language": "Python",
      "updatedAt": "2025-09-18T14:25:49Z",
      "scanDate": "2025-09-19T02:13:21.879843+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 12,
          "low": 2,
          "medium": 4,
          "total": 34,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-53643",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": " AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24762",
              "pkg": "fastapi",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-6984",
              "pkg": "langchain-community",
              "severity": "HIGH",
              "title": "Langchain Community Vulnerable to XML External Entity (XXE) Attacks"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53366",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53365",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53366",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53365",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48379",
              "pkg": "pillow",
              "severity": "HIGH",
              "title": "Pillow vulnerability can cause write buffer overflow on BCn encoding"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48379",
              "pkg": "pillow",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24762",
              "pkg": "python-multipart",
              "severity": "HIGH",
              "title": "python-multipart vulnerable to Content-Type Header ReDoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53981",
              "pkg": "python-multipart",
              "severity": "HIGH",
              "title": "Denial of service (DoS) via deformation `multipart/form-data` boundary"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-35195",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests `Session` object does not verify requests after making first request with verify=False"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54121",
              "pkg": "starlette",
              "severity": "MODERATE",
              "title": "Starlette has possible denial-of-service vector when parsing large files in multipart forms"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-46455",
              "pkg": "unstructured",
              "severity": "MODERATE",
              "title": "unstructured XML External Entity (XXE)"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50182",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 does not control redirects in browsers and Node.js"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50181",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53643",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": " AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24762",
              "pkg": "fastapi",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27516",
              "pkg": "jinja2",
              "severity": "MODERATE",
              "title": "Jinja2 vulnerable to sandbox breakout through attr filter selecting format method"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-56201",
              "pkg": "jinja2",
              "severity": "MODERATE",
              "title": "Jinja has a sandbox breakout through malicious filenames"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-22195",
              "pkg": "jinja2",
              "severity": "MODERATE",
              "title": "Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34064",
              "pkg": "jinja2",
              "severity": "MODERATE",
              "title": "Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-56326",
              "pkg": "jinja2",
              "severity": "MODERATE",
              "title": "Jinja has a sandbox breakout through indirect reference to format method"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-6984",
              "pkg": "langchain-community",
              "severity": "HIGH",
              "title": "Langchain Community Vulnerable to XML External Entity (XXE) Attacks"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53366",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53365",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48379",
              "pkg": "pillow",
              "severity": "HIGH",
              "title": "Pillow vulnerability can cause write buffer overflow on BCn encoding"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48379",
              "pkg": "pillow",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-55197",
              "pkg": "pypdf",
              "severity": "MODERATE",
              "title": "PyPDF's Manipulated FlateDecode streams can exhaust RAM"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54121",
              "pkg": "starlette",
              "severity": "MODERATE",
              "title": "Starlette has possible denial-of-service vector when parsing large files in multipart forms"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50182",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 does not control redirects in browsers and Node.js"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50181",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 5
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "github-mcp-server",
      "owner": "github",
      "fullName": "github/github-mcp-server",
      "url": "https://github.com/github/github-mcp-server",
      "stars": 22740,
      "description": "GitHub's official MCP Server",
      "language": "Go",
      "updatedAt": "2025-09-18T16:29:10Z",
      "scanDate": "2025-09-19T02:13:29.673186+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 5,
          "total": 6,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-2464-8j7c-4cjm",
              "pkg": "github.com/go-viper/mapstructure/v2",
              "severity": "MODERATE",
              "title": "go-viper's mapstructure May Leak Sensitive Information in Logs When Processing Malformed Data"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-2464-8j7c-4cjm",
              "pkg": "github.com/go-viper/mapstructure/v2",
              "severity": "MEDIUM",
              "title": "Go-viper's mapstructure May Leak Sensitive Information in Logs in github.com/go-viper/mapstructure"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": true,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 91,
      "errors": []
    },
    {
      "name": "UI-TARS-desktop",
      "owner": "bytedance",
      "fullName": "bytedance/UI-TARS-desktop",
      "url": "https://github.com/bytedance/UI-TARS-desktop",
      "stars": 18847,
      "description": "The Open-Source Multimodal AI Agent Stack: Connecting Cutting-Edge AI Models and Agent Infra",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T13:33:39Z",
      "scanDate": "2025-09-19T02:13:36.651532+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 1,
          "high": 4,
          "low": 7,
          "medium": 0,
          "total": 27,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/helpers",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/runtime",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-2792",
              "pkg": "@mozilla/readability",
              "severity": "LOW",
              "title": "@mozilla/readability Denial of Service through Regex"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-25288",
              "pkg": "@octokit/plugin-paginate-rest",
              "severity": "MODERATE",
              "title": "@octokit/plugin-paginate-rest has a Regular Expression in iterator Leads to ReDoS Vulnerability Due to Catastrophic Backtracking"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-25290",
              "pkg": "@octokit/request",
              "severity": "MODERATE",
              "title": "@octokit/request has a Regular Expression in fetchWrapper that Leads to ReDoS Vulnerability Due to Catastrophic Backtracking"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-25289",
              "pkg": "@octokit/request-error",
              "severity": "MODERATE",
              "title": "@octokit/request-error has a Regular Expression in index that Leads to ReDoS Vulnerability Due to Catastrophic Backtracking"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27152",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-55305",
              "pkg": "electron",
              "severity": "MODERATE",
              "title": "Electron has ASAR Integrity Bypass via resource modification"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-55305",
              "pkg": "electron",
              "severity": "MODERATE",
              "title": "Electron has ASAR Integrity Bypass via resource modification"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-7783",
              "pkg": "form-data",
              "severity": "CRITICAL",
              "title": "form-data uses unsafe random function in form-data for choosing boundary"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-4067",
              "pkg": "micromatch",
              "severity": "MODERATE",
              "title": "Regular Expression Denial of Service (ReDoS) in micromatch"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-43865",
              "pkg": "react-router",
              "severity": "HIGH",
              "title": "React Router allows pre-render data spoofing on React-Router framework mode"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48387",
              "pkg": "tar-fs",
              "severity": "HIGH",
              "title": "tar-fs can extract outside the specified dir with a specific tarball"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47279",
              "pkg": "undici",
              "severity": "LOW",
              "title": "undici Denial of Service attack via bad certificate data"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-30208",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite bypasses server.fs.deny when using ?raw??"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-31125",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite has a `server.fs.deny` bypassed for `inline` and `raw` with `?import` query"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-31486",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite allows server.fs.deny to be bypassed with .svg or relative paths"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-32395",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite has an `server.fs.deny` bypass with an invalid `request-target`"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-46565",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite's server.fs.deny bypassed with /. for files under project root"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 0,
          "packages": {}
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": true,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 44,
      "errors": []
    },
    {
      "name": "MaxKB",
      "owner": "1Panel-dev",
      "fullName": "1Panel-dev/MaxKB",
      "url": "https://github.com/1Panel-dev/MaxKB",
      "stars": 18399,
      "description": "🔥 MaxKB is an open-source platform for building enterprise-grade agents.  MaxKB 是强大易用的开源企业级智能体平台。",
      "language": "Python",
      "updatedAt": "2025-09-18T15:19:58Z",
      "scanDate": "2025-09-19T02:14:10.575281+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "activepieces",
      "owner": "activepieces",
      "fullName": "activepieces/activepieces",
      "url": "https://github.com/activepieces/activepieces",
      "stars": 17961,
      "description": "AI Agents \u0026 MCPs \u0026 AI Workflow Automation • (~400 MCP servers for AI agents) • AI Automation / AI Agent with MCPs • AI Workflows \u0026 AI Agents • MCPs for AI Agents",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T17:07:40Z",
      "scanDate": "2025-09-19T02:14:14.494071+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 1,
          "info": 0,
          "low": 13,
          "moderate": 9,
          "total": 23
        },
        "osv": {
          "critical": 0,
          "high": 2,
          "low": 3,
          "medium": 0,
          "total": 8,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-8129",
              "pkg": "koa",
              "severity": "LOW",
              "title": "Koa Open Redirect via Referrer Header (User-Controlled)"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47829",
              "pkg": "pnpm",
              "severity": "MODERATE",
              "title": "pnpm uses the md5 path shortening function causes packet paths to coincide, which causes indirect packet overwriting"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53382",
              "pkg": "prismjs",
              "severity": "MODERATE",
              "title": "PrismJS DOM Clobbering vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            }
          ]
        },
        "outdated": {
          "count": 304,
          "packages": {
            "@activepieces/import-fresh-webpack": {
              "dependent": "activepieces",
              "latest": "3.3.0",
              "wanted": "3.3.0"
            },
            "@ai-sdk/anthropic": {
              "dependent": "activepieces",
              "latest": "2.0.17",
              "wanted": "2.0.3"
            },
            "@ai-sdk/azure": {
              "dependent": "activepieces",
              "latest": "2.0.32",
              "wanted": "2.0.12"
            },
            "@ai-sdk/google": {
              "dependent": "activepieces",
              "latest": "2.0.14",
              "wanted": "2.0.6"
            },
            "@ai-sdk/openai": {
              "dependent": "activepieces",
              "latest": "2.0.32",
              "wanted": "2.0.12"
            },
            "@ai-sdk/replicate": {
              "dependent": "activepieces",
              "latest": "1.0.9",
              "wanted": "1.0.3"
            },
            "@anthropic-ai/sdk": {
              "dependent": "activepieces",
              "latest": "0.63.0",
              "wanted": "0.39.0"
            },
            "@atproto/api": {
              "dependent": "activepieces",
              "latest": "0.16.9",
              "wanted": "0.16.0"
            },
            "@authenio/samlify-node-xmllint": {
              "dependent": "activepieces",
              "latest": "2.0.0",
              "wanted": "2.0.0"
            },
            "@aws-sdk/client-s3": {
              "dependent": "activepieces",
              "latest": "3.891.0",
              "wanted": "3.637.0"
            },
            "@aws-sdk/s3-request-presigner": {
              "dependent": "activepieces",
              "latest": "3.891.0",
              "wanted": "3.658.1"
            },
            "@azure/communication-email": {
              "dependent": "activepieces",
              "latest": "1.0.0",
              "wanted": "1.0.0"
            },
            "@azure/openai": {
              "dependent": "activepieces",
              "latest": "2.0.0",
              "wanted": "1.0.0-beta.11"
            },
            "@babel/runtime": {
              "dependent": "activepieces",
              "latest": "7.28.4",
              "wanted": "7.26.10"
            },
            "@bull-board/api": {
              "dependent": "activepieces",
              "latest": "6.12.7",
              "wanted": "6.10.1"
            },
            "@bull-board/fastify": {
              "dependent": "activepieces",
              "latest": "6.12.7",
              "wanted": "6.10.1"
            },
            "@codemirror/lang-javascript": {
              "dependent": "activepieces",
              "latest": "6.2.4",
              "wanted": "6.2.2"
            },
            "@codemirror/lang-json": {
              "dependent": "activepieces",
              "latest": "6.0.2",
              "wanted": "6.0.1"
            },
            "@datastructures-js/queue": {
              "dependent": "activepieces",
              "latest": "4.3.0",
              "wanted": "4.2.3"
            },
            "@dnd-kit/core": {
              "dependent": "activepieces",
              "latest": "6.3.1",
              "wanted": "6.1.0"
            },
            "@dnd-kit/modifiers": {
              "dependent": "activepieces",
              "latest": "9.0.0",
              "wanted": "7.0.0"
            },
            "@dnd-kit/sortable": {
              "dependent": "activepieces",
              "latest": "10.0.0",
              "wanted": "8.0.0"
            },
            "@elevenlabs/elevenlabs-js": {
              "dependent": "activepieces",
              "latest": "2.15.0",
              "wanted": "2.4.1"
            },
            "@fastify/basic-auth": {
              "dependent": "activepieces",
              "latest": "6.2.0",
              "wanted": "6.2.0"
            },
            "@fastify/cors": {
              "dependent": "activepieces",
              "latest": "11.1.0",
              "wanted": "11.0.1"
            },
            "@fastify/formbody": {
              "dependent": "activepieces",
              "latest": "8.0.2",
              "wanted": "8.0.2"
            },
            "@fastify/http-proxy": {
              "dependent": "activepieces",
              "latest": "11.3.0",
              "wanted": "11.3.0"
            },
            "@fastify/multipart": {
              "dependent": "activepieces",
              "latest": "9.2.1",
              "wanted": "9.0.3"
            },
            "@fastify/otel": {
              "dependent": "activepieces",
              "latest": "0.9.4",
              "wanted": "0.9.3"
            },
            "@fastify/rate-limit": {
              "dependent": "activepieces",
              "latest": "10.3.0",
              "wanted": "10.3.0"
            },
            "@fastify/swagger": {
              "dependent": "activepieces",
              "latest": "9.5.1",
              "wanted": "9.5.1"
            },
            "@fastify/type-provider-typebox": {
              "dependent": "activepieces",
              "latest": "5.2.0",
              "wanted": "5.1.0"
            },
            "@google/generative-ai": {
              "dependent": "activepieces",
              "latest": "0.24.1",
              "wanted": "0.21.0"
            },
            "@hookform/resolvers": {
              "dependent": "activepieces",
              "latest": "5.2.2",
              "wanted": "3.9.0"
            },
            "@hyperdx/node-opentelemetry": {
              "dependent": "activepieces",
              "latest": "0.8.2",
              "wanted": "0.8.2"
            },
            "@mailchimp/mailchimp_marketing": {
              "dependent": "activepieces",
              "latest": "3.0.80",
              "wanted": "3.0.80"
            },
            "@mailerlite/mailerlite-nodejs": {
              "dependent": "activepieces",
              "latest": "1.5.0",
              "wanted": "1.1.0"
            },
            "@microsoft/microsoft-graph-client": {
              "dependent": "activepieces",
              "latest": "3.0.7",
              "wanted": "3.0.7"
            },
            "@microsoft/microsoft-graph-types": {
              "dependent": "activepieces",
              "latest": "2.40.0",
              "wanted": "2.40.0"
            },
            "@modelcontextprotocol/sdk": {
              "dependent": "activepieces",
              "latest": "1.18.1",
              "wanted": "1.11.0"
            },
            "@notionhq/client": {
              "dependent": "activepieces",
              "latest": "5.1.0",
              "wanted": "2.2.11"
            },
            "@nx/devkit": {
              "dependent": "activepieces",
              "latest": "21.5.2",
              "wanted": "21.1.2"
            },
            "@nx/nx-darwin-arm64": {
              "dependent": "activepieces",
              "latest": "21.5.2",
              "wanted": "21.1.2"
            },
            "@nx/nx-darwin-x64": {
              "dependent": "activepieces",
              "latest": "21.5.2",
              "wanted": "18.0.4"
            },
            "@nx/nx-linux-arm-gnueabihf": {
              "dependent": "activepieces",
              "latest": "21.5.2",
              "wanted": "18.0.4"
            },
            "@nx/nx-linux-x64-gnu": {
              "dependent": "activepieces",
              "latest": "21.5.2",
              "wanted": "18.0.4"
            },
            "@nx/nx-win32-x64-msvc": {
              "dependent": "activepieces",
              "latest": "21.5.2",
              "wanted": "18.0.4"
            },
            "@octokit/rest": {
              "dependent": "activepieces",
              "latest": "22.0.0",
              "wanted": "21.1.1"
            },
            "@onfleet/node-onfleet": {
              "dependent": "activepieces",
              "latest": "1.3.8",
              "wanted": "1.3.3"
            },
            "@opentelemetry/api": {
              "dependent": "activepieces",
              "latest": "1.9.0",
              "wanted": "1.9.0"
            },
            "@opentelemetry/api-logs": {
              "dependent": "activepieces",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/auto-instrumentations-node": {
              "dependent": "activepieces",
              "latest": "0.64.1",
              "wanted": "0.62.0"
            },
            "@opentelemetry/exporter-metrics-otlp-http": {
              "dependent": "activepieces",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/exporter-metrics-otlp-proto": {
              "dependent": "activepieces",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/exporter-trace-otlp-http": {
              "dependent": "activepieces",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/sdk-logs": {
              "dependent": "activepieces",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/sdk-metrics": {
              "dependent": "activepieces",
              "latest": "2.1.0",
              "wanted": "2.0.1"
            },
            "@opentelemetry/sdk-node": {
              "dependent": "activepieces",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@qdrant/js-client-rest": {
              "dependent": "activepieces",
              "latest": "1.15.1",
              "wanted": "1.7.0"
            },
            "@radix-ui/react-accordion": {
              "dependent": "activepieces",
              "latest": "1.2.12",
              "wanted": "1.2.4"
            },
            "@radix-ui/react-avatar": {
              "dependent": "activepieces",
              "latest": "1.1.10",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-checkbox": {
              "dependent": "activepieces",
              "latest": "1.3.3",
              "wanted": "1.1.1"
            },
            "@radix-ui/react-collapsible": {
              "dependent": "activepieces",
              "latest": "1.1.12",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-context-menu": {
              "dependent": "activepieces",
              "latest": "2.2.16",
              "wanted": "2.2.2"
            },
            "@radix-ui/react-dialog": {
              "dependent": "activepieces",
              "latest": "1.1.15",
              "wanted": "1.1.1"
            },
            "@radix-ui/react-dropdown-menu": {
              "dependent": "activepieces",
              "latest": "2.1.16",
              "wanted": "2.1.1"
            },
            "@radix-ui/react-icons": {
              "dependent": "activepieces",
              "latest": "1.3.2",
              "wanted": "1.3.0"
            },
            "@radix-ui/react-label": {
              "dependent": "activepieces",
              "latest": "2.1.7",
              "wanted": "2.1.0"
            },
            "@radix-ui/react-popover": {
              "dependent": "activepieces",
              "latest": "1.1.15",
              "wanted": "1.1.1"
            },
            "@radix-ui/react-progress": {
              "dependent": "activepieces",
              "latest": "1.1.7",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-radio-group": {
              "dependent": "activepieces",
              "latest": "1.3.8",
              "wanted": "1.2.0"
            },
            "@radix-ui/react-scroll-area": {
              "dependent": "activepieces",
              "latest": "1.2.10",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-select": {
              "dependent": "activepieces",
              "latest": "2.2.6",
              "wanted": "2.1.1"
            },
            "@radix-ui/react-separator": {
              "dependent": "activepieces",
              "latest": "1.1.7",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-slider": {
              "dependent": "activepieces",
              "latest": "1.3.6",
              "wanted": "1.3.5"
            },
            "@radix-ui/react-slot": {
              "dependent": "activepieces",
              "latest": "1.2.3",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-switch": {
              "dependent": "activepieces",
              "latest": "1.2.6",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-tabs": {
              "dependent": "activepieces",
              "latest": "1.1.13",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-toast": {
              "dependent": "activepieces",
              "latest": "1.2.15",
              "wanted": "1.2.1"
            },
            "@radix-ui/react-toggle": {
              "dependent": "activepieces",
              "latest": "1.1.10",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-tooltip": {
              "dependent": "activepieces",
              "latest": "1.2.8",
              "wanted": "1.1.2"
            },
            "@rollup/rollup-darwin-arm64": {
              "dependent": "activepieces",
              "latest": "4.50.2",
              "wanted": "4.20.0"
            },
            "@rollup/rollup-linux-arm64-gnu": {
              "dependent": "activepieces",
              "latest": "4.50.2",
              "wanted": "4.20.0"
            },
            "@rollup/wasm-node": {
              "dependent": "activepieces",
              "latest": "4.50.2",
              "wanted": "4.21.2"
            },
            "@runware/sdk-js": {
              "dependent": "activepieces",
              "latest": "1.1.46",
              "wanted": "1.1.44"
            },
            "@segment/analytics-next": {
              "dependent": "activepieces",
              "latest": "1.81.1",
              "wanted": "1.72.0"
            },
            "@segment/analytics-node": {
              "dependent": "activepieces",
              "latest": "2.3.0",
              "wanted": "2.2.0"
            },
            "@sendgrid/mail": {
              "dependent": "activepieces",
              "latest": "8.1.5",
              "wanted": "8.0.0"
            },
            "@sentry/node": {
              "dependent": "activepieces",
              "latest": "10.12.0",
              "wanted": "7.120.0"
            },
            "@sinclair/typebox": {
              "dependent": "activepieces",
              "latest": "0.34.41",
              "wanted": "0.34.11"
            },
            "@slack/web-api": {
              "dependent": "activepieces",
              "latest": "7.10.0",
              "wanted": "7.9.0"
            },
            "@socket.io/redis-adapter": {
              "dependent": "activepieces",
              "latest": "8.3.0",
              "wanted": "8.2.1"
            },
            "@supabase/supabase-js": {
              "dependent": "activepieces",
              "latest": "2.57.4",
              "wanted": "2.49.9"
            },
            "@tanstack/react-query": {
              "dependent": "activepieces",
              "latest": "5.89.0",
              "wanted": "5.51.1"
            },
            "@tanstack/react-table": {
              "dependent": "activepieces",
              "latest": "8.21.3",
              "wanted": "8.19.2"
            },
            "@tanstack/react-virtual": {
              "dependent": "activepieces",
              "latest": "3.13.12",
              "wanted": "3.13.11"
            },
            "@tiptap/extension-mention": {
              "dependent": "activepieces",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/extension-placeholder": {
              "dependent": "activepieces",
              "latest": "3.4.4",
              "wanted": "2.5.5"
            },
            "@tiptap/extension-typography": {
              "dependent": "activepieces",
              "latest": "3.4.4",
              "wanted": "2.26.1"
            },
            "@tiptap/pm": {
              "dependent": "activepieces",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/react": {
              "dependent": "activepieces",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/starter-kit": {
              "dependent": "activepieces",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/suggestion": {
              "dependent": "activepieces",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tryfabric/martian": {
              "dependent": "activepieces",
              "latest": "1.2.4",
              "wanted": "1.2.0"
            },
            "@types/amqplib": {
              "dependent": "activepieces",
              "latest": "0.10.7",
              "wanted": "0.10.5"
            },
            "@types/docusign-esign": {
              "dependent": "activepieces",
              "latest": "5.19.9",
              "wanted": "5.19.9"
            },
            "@types/imapflow": {
              "dependent": "activepieces",
              "latest": "1.0.23",
              "wanted": "1.0.18"
            },
            "@types/js-yaml": {
              "dependent": "activepieces",
              "latest": "4.0.9",
              "wanted": "4.0.9"
            },
            "@types/pg-format": {
              "dependent": "activepieces",
              "latest": "1.0.5",
              "wanted": "1.0.5"
            },
            "@types/showdown": {
              "dependent": "activepieces",
              "latest": "2.0.6",
              "wanted": "2.0.6"
            },
            "@uiw/codemirror-theme-github": {
              "dependent": "activepieces",
              "latest": "4.25.2",
              "wanted": "4.23.0"
            },
            "@uiw/react-codemirror": {
              "dependent": "activepieces",
              "latest": "4.25.2",
              "wanted": "4.23.0"
            },
            "@xyflow/react": {
              "dependent": "activepieces",
              "latest": "12.8.5",
              "wanted": "12.3.5"
            },
            "ai": {
              "dependent": "activepieces",
              "latest": "5.0.45",
              "wanted": "5.0.12"
            },
            "airtable": {
              "dependent": "activepieces",
              "latest": "0.12.2",
              "wanted": "0.11.6"
            },
            "ajv": {
              "dependent": "activepieces",
              "latest": "8.17.1",
              "wanted": "8.12.0"
            },
            "amqplib": {
              "dependent": "activepieces",
              "latest": "0.10.9",
              "wanted": "0.10.4"
            },
            "assemblyai": {
              "dependent": "activepieces",
              "latest": "4.16.1",
              "wanted": "4.7.0"
            },
            "async-mutex": {
              "dependent": "activepieces",
              "latest": "0.5.0",
              "wanted": "0.4.0"
            },
            "axios": {
              "dependent": "activepieces",
              "latest": "1.12.2",
              "wanted": "1.8.3"
            },
            "axios-retry": {
              "dependent": "activepieces",
              "latest": "4.5.0",
              "wanted": "4.4.1"
            },
            "basic-ftp": {
              "dependent": "activepieces",
              "latest": "5.0.5",
              "wanted": "5.0.5"
            },
            "bcrypt": {
              "dependent": "activepieces",
              "latest": "6.0.0",
              "wanted": "6.0.0"
            },
            "boring-avatars": {
              "dependent": "activepieces",
              "latest": "2.0.1",
              "wanted": "1.11.2"
            },
            "buffer": {
              "dependent": "activepieces",
              "latest": "6.0.3",
              "wanted": "6.0.3"
            },
            "bullmq": {
              "dependent": "activepieces",
              "latest": "5.58.5",
              "wanted": "5.28.1"
            },
            "bullmq-otel": {
              "dependent": "activepieces",
              "latest": "1.0.1",
              "wanted": "1.0.1"
            },
            "checkly": {
              "dependent": "activepieces",
              "latest": "6.5.0",
              "wanted": "6.1.1"
            },
            "cheerio": {
              "dependent": "activepieces",
              "latest": "1.1.2",
              "wanted": "1.0.0-rc.12"
            },
            "chokidar": {
              "dependent": "activepieces",
              "latest": "4.0.3",
              "wanted": "3.6.0"
            },
            "class-variance-authority": {
              "dependent": "activepieces",
              "latest": "0.7.1",
              "wanted": "0.7.0"
            },
            "clear-module": {
              "dependent": "activepieces",
              "latest": "4.1.2",
              "wanted": "4.1.2"
            },
            "cli-table3": {
              "dependent": "activepieces",
              "latest": "0.6.5",
              "wanted": "0.6.3"
            },
            "clipboard": {
              "dependent": "activepieces",
              "latest": "2.0.11",
              "wanted": "2.0.11"
            },
            "clsx": {
              "dependent": "activepieces",
              "latest": "2.1.1",
              "wanted": "2.1.1"
            },
            "cmdk": {
              "dependent": "activepieces",
              "latest": "1.1.1",
              "wanted": "1.1.1"
            },
            "codemirror": {
              "dependent": "activepieces",
              "latest": "6.0.2",
              "wanted": "5.65.14"
            },
            "color": {
              "dependent": "activepieces",
              "latest": "5.0.2",
              "wanted": "4.2.3"
            },
            "commander": {
              "dependent": "activepieces",
              "latest": "14.0.1",
              "wanted": "11.1.0"
            },
            "compare-versions": {
              "dependent": "activepieces",
              "latest": "6.1.1",
              "wanted": "6.1.0"
            },
            "concat": {
              "dependent": "activepieces",
              "latest": "1.0.3",
              "wanted": "1.0.3"
            },
            "contrast-color": {
              "dependent": "activepieces",
              "latest": "1.0.1",
              "wanted": "1.0.1"
            },
            "cron-validator": {
              "dependent": "activepieces",
              "latest": "1.4.0",
              "wanted": "1.3.1"
            },
            "cronstrue": {
              "dependent": "activepieces",
              "latest": "3.3.0",
              "wanted": "2.31.0"
            },
            "cross-spawn": {
              "dependent": "activepieces",
              "latest": "7.0.6",
              "wanted": "7.0.6"
            },
            "crypto-js": {
              "dependent": "activepieces",
              "latest": "4.2.0",
              "wanted": "4.2.0"
            },
            "csv-parse": {
              "dependent": "activepieces",
              "latest": "6.1.0",
              "wanted": "5.6.0"
            },
            "csv-reader": {
              "dependent": "activepieces",
              "latest": "1.0.12",
              "wanted": "1.0.12"
            },
            "csv-stringify": {
              "dependent": "activepieces",
              "latest": "6.6.0",
              "wanted": "6.5.2"
            },
            "date-fns": {
              "dependent": "activepieces",
              "latest": "4.1.0",
              "wanted": "3.6.0"
            },
            "dayjs": {
              "dependent": "activepieces",
              "latest": "1.11.18",
              "wanted": "1.11.9"
            },
            "decompress": {
              "dependent": "activepieces",
              "latest": "4.2.1",
              "wanted": "4.2.1"
            },
            "deep-equal": {
              "dependent": "activepieces",
              "latest": "2.2.3",
              "wanted": "2.2.2"
            },
            "deepmerge-ts": {
              "dependent": "activepieces",
              "latest": "7.1.5",
              "wanted": "7.1.0"
            },
            "docusign-esign": {
              "dependent": "activepieces",
              "latest": "8.4.0",
              "wanted": "8.1.0"
            },
            "drip-nodejs": {
              "dependent": "activepieces",
              "latest": "3.1.4",
              "wanted": "3.1.2"
            },
            "embla-carousel-react": {
              "dependent": "activepieces",
              "latest": "8.6.0",
              "wanted": "8.1.8"
            },
            "ethers": {
              "dependent": "activepieces",
              "latest": "6.15.0",
              "wanted": "6.15.0"
            },
            "eventsource-parser": {
              "dependent": "activepieces",
              "latest": "3.0.6",
              "wanted": "3.0.2"
            },
            "exifreader": {
              "dependent": "activepieces",
              "latest": "4.31.2",
              "wanted": "4.20.0"
            },
            "fast-glob": {
              "dependent": "activepieces",
              "latest": "3.3.3",
              "wanted": "3.3.3"
            },
            "fastify": {
              "dependent": "activepieces",
              "latest": "5.6.0",
              "wanted": "5.4.0"
            },
            "fastify-favicon": {
              "dependent": "activepieces",
              "latest": "5.0.0",
              "wanted": "5.0.0"
            },
            "fastify-plugin": {
              "dependent": "activepieces",
              "latest": "5.0.1",
              "wanted": "5.0.1"
            },
            "fastify-raw-body": {
              "dependent": "activepieces",
              "latest": "5.0.0",
              "wanted": "5.0.0"
            },
            "fastify-socket": {
              "dependent": "activepieces",
              "latest": "5.1.4",
              "wanted": "5.1.2"
            },
            "fastify-xml-body-parser": {
              "dependent": "activepieces",
              "latest": "2.2.0",
              "wanted": "2.2.0"
            },
            "feedparser": {
              "dependent": "activepieces",
              "latest": "2.2.10",
              "wanted": "2.2.10"
            },
            "fetch-retry": {
              "dependent": "activepieces",
              "latest": "6.0.0",
              "wanted": "6.0.0"
            },
            "firebase-scrypt": {
              "dependent": "activepieces",
              "latest": "2.2.0",
              "wanted": "2.2.0"
            },
            "flowtoken": {
              "dependent": "activepieces",
              "latest": "1.0.40",
              "wanted": "1.0.40"
            },
            "font-awesome": {
              "dependent": "activepieces",
              "latest": "4.7.0",
              "wanted": "4.7.0"
            },
            "form-data": {
              "dependent": "activepieces",
              "latest": "4.0.4",
              "wanted": "4.0.4"
            },
            "framer-motion": {
              "dependent": "activepieces",
              "latest": "12.23.15",
              "wanted": "12.15.0"
            },
            "frimousse": {
              "dependent": "activepieces",
              "latest": "0.3.0",
              "wanted": "0.2.0"
            },
            "fs-extra": {
              "dependent": "activepieces",
              "latest": "11.3.2",
              "wanted": "11.2.0"
            },
            "fuse.js": {
              "dependent": "activepieces",
              "latest": "7.1.0",
              "wanted": "7.0.0"
            },
            "google-auth-library": {
              "dependent": "activepieces",
              "latest": "10.3.0",
              "wanted": "8.9.0"
            },
            "googleapis": {
              "dependent": "activepieces",
              "latest": "160.0.0",
              "wanted": "129.0.0"
            },
            "http-status-codes": {
              "dependent": "activepieces",
              "latest": "2.3.0",
              "wanted": "2.2.0"
            },
            "https-proxy-agent": {
              "dependent": "activepieces",
              "latest": "7.0.6",
              "wanted": "7.0.4"
            },
            "i18next": {
              "dependent": "activepieces",
              "latest": "25.5.2",
              "wanted": "23.13.0"
            },
            "i18next-browser-languagedetector": {
              "dependent": "activepieces",
              "latest": "8.2.0",
              "wanted": "8.0.0"
            },
            "i18next-http-backend": {
              "dependent": "activepieces",
              "latest": "3.0.2",
              "wanted": "2.5.2"
            },
            "i18next-icu": {
              "dependent": "activepieces",
              "latest": "2.4.0",
              "wanted": "2.3.0"
            },
            "imapflow": {
              "dependent": "activepieces",
              "latest": "1.0.196",
              "wanted": "1.0.152"
            },
            "intercom-client": {
              "dependent": "activepieces",
              "latest": "6.4.0",
              "wanted": "6.0.0"
            },
            "intl-messageformat": {
              "dependent": "activepieces",
              "latest": "10.7.16",
              "wanted": "10.5.14"
            },
            "ioredis": {
              "dependent": "activepieces",
              "latest": "5.7.0",
              "wanted": "5.4.1"
            },
            "ioredis-mock": {
              "dependent": "activepieces",
              "latest": "8.9.0",
              "wanted": "8.9.0"
            },
            "is-base64": {
              "dependent": "activepieces",
              "latest": "1.1.0",
              "wanted": "1.1.0"
            },
            "isolated-vm": {
              "dependent": "activepieces",
              "latest": "6.0.1",
              "wanted": "5.0.1"
            },
            "js-yaml": {
              "dependent": "activepieces",
              "latest": "4.1.0",
              "wanted": "4.1.0"
            },
            "jsdom": {
              "dependent": "activepieces",
              "latest": "27.0.0",
              "wanted": "23.0.1"
            },
            "jshint": {
              "dependent": "activepieces",
              "latest": "2.13.6",
              "wanted": "2.13.6"
            },
            "json-server": {
              "dependent": "activepieces",
              "latest": "1.0.0-beta.3",
              "wanted": "1.0.0-beta.0"
            },
            "json-to-pretty-yaml": {
              "dependent": "activepieces",
              "latest": "1.2.2",
              "wanted": "1.2.2"
            },
            "json2xml": {
              "dependent": "activepieces",
              "latest": "0.1.3",
              "wanted": "0.1.3"
            },
            "jsoneditor": {
              "dependent": "activepieces",
              "latest": "10.4.1",
              "wanted": "10.0.3"
            },
            "jsonlint-mod": {
              "dependent": "activepieces",
              "latest": "1.7.6",
              "wanted": "1.7.6"
            },
            "jsonrepair": {
              "dependent": "activepieces",
              "latest": "3.13.0",
              "wanted": "3.2.0"
            },
            "jsonwebtoken": {
              "dependent": "activepieces",
              "latest": "9.0.2",
              "wanted": "9.0.1"
            },
            "jszip": {
              "dependent": "activepieces",
              "latest": "3.10.1",
              "wanted": "3.10.1"
            },
            "jwks-rsa": {
              "dependent": "activepieces",
              "latest": "3.2.0",
              "wanted": "3.1.0"
            },
            "jwt-decode": {
              "dependent": "activepieces",
              "latest": "4.0.0",
              "wanted": "4.0.0"
            },
            "lottie-web": {
              "dependent": "activepieces",
              "latest": "5.13.0",
              "wanted": "5.12.2"
            },
            "lucide-react": {
              "dependent": "activepieces",
              "latest": "0.544.0",
              "wanted": "0.407.0"
            },
            "mailparser": {
              "dependent": "activepieces",
              "latest": "3.7.4",
              "wanted": "3.6.7"
            },
            "marked": {
              "dependent": "activepieces",
              "latest": "16.3.0",
              "wanted": "4.3.0"
            },
            "mime": {
              "dependent": "activepieces",
              "latest": "4.1.0",
              "wanted": "4.0.1"
            },
            "mime-types": {
              "dependent": "activepieces",
              "latest": "3.0.1",
              "wanted": "2.1.35"
            },
            "mintlify": {
              "dependent": "activepieces",
              "latest": "4.2.117",
              "wanted": "4.0.395"
            },
            "monday-sdk-js": {
              "dependent": "activepieces",
              "latest": "0.5.6",
              "wanted": "0.5.2"
            },
            "mongodb": {
              "dependent": "activepieces",
              "latest": "6.20.0",
              "wanted": "6.15.0"
            },
            "motion": {
              "dependent": "activepieces",
              "latest": "12.23.15",
              "wanted": "12.16.0"
            },
            "mustache": {
              "dependent": "activepieces",
              "latest": "4.2.0",
              "wanted": "4.2.0"
            },
            "nanoid": {
              "dependent": "activepieces",
              "latest": "5.1.5",
              "wanted": "3.3.8"
            },
            "next-themes": {
              "dependent": "activepieces",
              "latest": "0.4.6",
              "wanted": "0.4.6"
            },
            "node-cron": {
              "dependent": "activepieces",
              "latest": "4.2.1",
              "wanted": "3.0.3"
            },
            "nodemailer": {
              "dependent": "activepieces",
              "latest": "7.0.6",
              "wanted": "6.9.9"
            },
            "notion-to-md": {
              "dependent": "activepieces",
              "latest": "3.1.9",
              "wanted": "3.1.1"
            },
            "nx-cloud": {
              "dependent": "activepieces",
              "latest": "19.1.0",
              "wanted": "19.1.0"
            },
            "object-sizeof": {
              "dependent": "activepieces",
              "latest": "2.6.5",
              "wanted": "2.6.3"
            },
            "openai": {
              "dependent": "activepieces",
              "latest": "5.21.0",
              "wanted": "4.67.1"
            },
            "p-limit": {
              "dependent": "activepieces",
              "latest": "7.1.1",
              "wanted": "2.3.0"
            },
            "pako": {
              "dependent": "activepieces",
              "latest": "2.1.0",
              "wanted": "2.1.0"
            },
            "papaparse": {
              "dependent": "activepieces",
              "latest": "5.5.3",
              "wanted": "5.5.3"
            },
            "pg": {
              "dependent": "activepieces",
              "latest": "8.16.3",
              "wanted": "8.11.3"
            },
            "pg-format": {
              "dependent": "activepieces",
              "latest": "1.0.4",
              "wanted": "1.0.4"
            },
            "pickleparser": {
              "dependent": "activepieces",
              "latest": "0.2.1",
              "wanted": "0.1.0"
            },
            "pino-loki": {
              "dependent": "activepieces",
              "latest": "2.6.0",
              "wanted": "2.1.3"
            },
            "playwright": {
              "dependent": "activepieces",
              "latest": "1.55.0",
              "wanted": "1.52.0"
            },
            "posthog-js": {
              "dependent": "activepieces",
              "latest": "1.266.0",
              "wanted": "1.195.0"
            },
            "priority-queue-typescript": {
              "dependent": "activepieces",
              "latest": "2.0.3",
              "wanted": "1.0.1"
            },
            "prismjs": {
              "dependent": "activepieces",
              "latest": "1.30.0",
              "wanted": "1.30.0"
            },
            "promise-mysql": {
              "dependent": "activepieces",
              "latest": "5.2.0",
              "wanted": "5.2.0"
            },
            "qrcode": {
              "dependent": "activepieces",
              "latest": "1.5.4",
              "wanted": "1.5.4"
            },
            "qs": {
              "dependent": "activepieces",
              "latest": "6.14.0",
              "wanted": "6.11.2"
            },
            "react": {
              "dependent": "activepieces",
              "latest": "19.1.1",
              "wanted": "18.3.1"
            },
            "react-colorful": {
              "dependent": "activepieces",
              "latest": "5.6.1",
              "wanted": "5.6.1"
            },
            "react-data-grid": {
              "dependent": "activepieces",
              "latest": "7.0.0-beta.57",
              "wanted": "7.0.0-beta.47"
            },
            "react-day-picker": {
              "dependent": "activepieces",
              "latest": "9.10.0",
              "wanted": "8.10.1"
            },
            "react-dom": {
              "dependent": "activepieces",
              "latest": "19.1.1",
              "wanted": "18.3.1"
            },
            "react-error-boundary": {
              "dependent": "activepieces",
              "latest": "6.0.0",
              "wanted": "5.0.0"
            },
            "react-hook-form": {
              "dependent": "activepieces",
              "latest": "7.62.0",
              "wanted": "7.52.2"
            },
            "react-i18next": {
              "dependent": "activepieces",
              "latest": "15.7.3",
              "wanted": "15.0.1"
            },
            "react-json-view": {
              "dependent": "activepieces",
              "latest": "1.21.3",
              "wanted": "1.21.3"
            },
            "react-lottie": {
              "dependent": "activepieces",
              "latest": "1.2.10",
              "wanted": "1.2.4"
            },
            "react-markdown": {
              "dependent": "activepieces",
              "latest": "10.1.0",
              "wanted": "9.0.1"
            },
            "react-resizable-panels": {
              "dependent": "activepieces",
              "latest": "3.0.6",
              "wanted": "2.0.20"
            },
            "react-ripples": {
              "dependent": "activepieces",
              "latest": "2.2.1",
              "wanted": "2.2.1"
            },
            "react-router-dom": {
              "dependent": "activepieces",
              "latest": "7.9.1",
              "wanted": "6.11.2"
            },
            "react-syntax-highlighter": {
              "dependent": "activepieces",
              "latest": "15.6.6",
              "wanted": "15.4.2"
            },
            "react-textarea-autosize": {
              "dependent": "activepieces",
              "latest": "8.5.9",
              "wanted": "8.5.5"
            },
            "react-use": {
              "dependent": "activepieces",
              "latest": "17.6.0",
              "wanted": "17.5.1"
            },
            "recharts": {
              "dependent": "activepieces",
              "latest": "3.2.1",
              "wanted": "2.12.7"
            },
            "redlock": {
              "dependent": "activepieces",
              "latest": "5.0.0-beta.2",
              "wanted": "5.0.0-beta.2"
            },
            "remark-breaks": {
              "dependent": "activepieces",
              "latest": "4.0.0",
              "wanted": "4.0.0"
            },
            "remark-gfm": {
              "dependent": "activepieces",
              "latest": "4.0.1",
              "wanted": "4.0.0"
            },
            "replicate": {
              "dependent": "activepieces",
              "latest": "1.2.0",
              "wanted": "0.34.1"
            },
            "rollup": {
              "dependent": "activepieces",
              "latest": "4.50.2",
              "wanted": "4.22.5"
            },
            "rss-parser": {
              "dependent": "activepieces",
              "latest": "3.13.0",
              "wanted": "3.13.0"
            },
            "safe-flat": {
              "dependent": "activepieces",
              "latest": "2.1.0",
              "wanted": "2.1.0"
            },
            "samlify": {
              "dependent": "activepieces",
              "latest": "2.10.1",
              "wanted": "2.10.0"
            },
            "semver": {
              "dependent": "activepieces",
              "latest": "7.7.2",
              "wanted": "7.6.0"
            },
            "showdown": {
              "dependent": "activepieces",
              "latest": "2.1.0",
              "wanted": "2.1.0"
            },
            "simple-git": {
              "dependent": "activepieces",
              "latest": "3.28.0",
              "wanted": "3.21.0"
            },
            "slackify-markdown": {
              "dependent": "activepieces",
              "latest": "4.5.0",
              "wanted": "4.4.0"
            },
            "slugify": {
              "dependent": "activepieces",
              "latest": "1.6.6",
              "wanted": "1.6.6"
            },
            "snowflake-sdk": {
              "dependent": "activepieces",
              "latest": "2.2.0",
              "wanted": "1.9.3"
            },
            "soap": {
              "dependent": "activepieces",
              "latest": "1.4.1",
              "wanted": "1.1.10"
            },
            "socket.io": {
              "dependent": "activepieces",
              "latest": "4.8.1",
              "wanted": "4.8.1"
            },
            "socket.io-client": {
              "dependent": "activepieces",
              "latest": "4.8.1",
              "wanted": "4.7.5"
            },
            "sonner": {
              "dependent": "activepieces",
              "latest": "2.0.7",
              "wanted": "2.0.3"
            },
            "sqlite3": {
              "dependent": "activepieces",
              "latest": "5.1.7",
              "wanted": "5.1.7"
            },
            "sqlstring": {
              "dependent": "activepieces",
              "latest": "2.3.3",
              "wanted": "2.3.3"
            },
            "ssh2-sftp-client": {
              "dependent": "activepieces",
              "latest": "12.0.1",
              "wanted": "9.1.0"
            },
            "string-replace-async": {
              "dependent": "activepieces",
              "latest": "3.0.2",
              "wanted": "3.0.2"
            },
            "string-strip-html": {
              "dependent": "activepieces",
              "latest": "13.4.13",
              "wanted": "8.5.0"
            },
            "stripe": {
              "dependent": "activepieces",
              "latest": "18.5.0",
              "wanted": "18.2.1"
            },
            "tailwind-merge": {
              "dependent": "activepieces",
              "latest": "3.3.1",
              "wanted": "2.4.0"
            },
            "tailwind-scrollbar": {
              "dependent": "activepieces",
              "latest": "4.0.2",
              "wanted": "4.0.2"
            },
            "tailwindcss-animate": {
              "dependent": "activepieces",
              "latest": "1.0.7",
              "wanted": "1.0.7"
            },
            "tinycolor2": {
              "dependent": "activepieces",
              "latest": "1.6.0",
              "wanted": "1.6.0"
            },
            "tiptap-markdown": {
              "dependent": "activepieces",
              "latest": "0.9.0",
              "wanted": "0.8.10"
            },
            "tree-kill": {
              "dependent": "activepieces",
              "latest": "1.2.2",
              "wanted": "1.2.2"
            },
            "tsconfig-paths": {
              "dependent": "activepieces",
              "latest": "4.2.0",
              "wanted": "4.2.0"
            },
            "tslib": {
              "dependent": "activepieces",
              "latest": "2.8.1",
              "wanted": "2.6.2"
            },
            "turndown": {
              "dependent": "activepieces",
              "latest": "7.2.1",
              "wanted": "7.2.0"
            },
            "twitter-api-v2": {
              "dependent": "activepieces",
              "latest": "1.27.0",
              "wanted": "1.15.1"
            },
            "typeorm": {
              "dependent": "activepieces",
              "latest": "0.3.26",
              "wanted": "0.3.18"
            },
            "url": {
              "dependent": "activepieces",
              "latest": "0.11.4",
              "wanted": "0.11.3"
            },
            "use-debounce": {
              "dependent": "activepieces",
              "latest": "10.0.6",
              "wanted": "10.0.1"
            },
            "use-deep-compare-effect": {
              "dependent": "activepieces",
              "latest": "1.8.1",
              "wanted": "1.8.1"
            },
            "use-ripple-hook": {
              "dependent": "activepieces",
              "latest": "1.0.24",
              "wanted": "1.0.24"
            },
            "usehooks-ts": {
              "dependent": "activepieces",
              "latest": "3.1.1",
              "wanted": "3.1.0"
            },
            "vaul": {
              "dependent": "activepieces",
              "latest": "1.1.2",
              "wanted": "1.1.2"
            },
            "write-file-atomic": {
              "dependent": "activepieces",
              "latest": "6.0.0",
              "wanted": "5.0.1"
            },
            "xml2js": {
              "dependent": "activepieces",
              "latest": "0.6.2",
              "wanted": "0.6.2"
            },
            "xmlrpc": {
              "dependent": "activepieces",
              "latest": "1.3.2",
              "wanted": "1.3.2"
            },
            "yaml": {
              "dependent": "activepieces",
              "latest": "2.8.1",
              "wanted": "2.4.1"
            },
            "zod": {
              "dependent": "activepieces",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            },
            "zone.js": {
              "dependent": "activepieces",
              "latest": "0.15.1",
              "wanted": "0.14.4"
            },
            "zustand": {
              "dependent": "activepieces",
              "latest": "5.0.8",
              "wanted": "4.5.4"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": false,
          "score": 5
        }
      },
      "securityScore": 5,
      "errors": []
    },
    {
      "name": "serena",
      "owner": "oraios",
      "fullName": "oraios/serena",
      "url": "https://github.com/oraios/serena",
      "stars": 12663,
      "description": "A powerful coding agent toolkit providing semantic retrieval and editing capabilities (MCP server \u0026 other integrations)",
      "language": "Python",
      "updatedAt": "2025-09-18T17:08:00Z",
      "scanDate": "2025-09-19T02:15:28.406218+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 5
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "trigger.dev",
      "owner": "triggerdotdev",
      "fullName": "triggerdotdev/trigger.dev",
      "url": "https://github.com/triggerdotdev/trigger.dev",
      "stars": 12417,
      "description": "Trigger.dev – build and deploy fully‑managed AI agents and workflows",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:43:03Z",
      "scanDate": "2025-09-19T02:15:30.635553+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 3,
          "high": 13,
          "low": 11,
          "medium": 0,
          "total": 59,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/helpers",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/runtime",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/runtime",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/runtime",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/runtime",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45133",
              "pkg": "@babel/traverse",
              "severity": "CRITICAL",
              "title": "Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47764",
              "pkg": "cookie",
              "severity": "LOW",
              "title": "cookie accepts cookie name, path, and domain with out of bounds characters"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47764",
              "pkg": "cookie",
              "severity": "LOW",
              "title": "cookie accepts cookie name, path, and domain with out of bounds characters"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-21538",
              "pkg": "cross-spawn",
              "severity": "HIGH",
              "title": "Regular Expression Denial of Service (ReDoS) in cross-spawn"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-21538",
              "pkg": "cross-spawn",
              "severity": "HIGH",
              "title": "Regular Expression Denial of Service (ReDoS) in cross-spawn"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-21538",
              "pkg": "cross-spawn",
              "severity": "HIGH",
              "title": "Regular Expression Denial of Service (ReDoS) in cross-spawn"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-46233",
              "pkg": "crypto-js",
              "severity": "CRITICAL",
              "title": "crypto-js PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-32014",
              "pkg": "estree-util-value-to-estree",
              "severity": "MODERATE",
              "title": "estree-util-value-to-estree allows prototype pollution in generated ESTree"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-46653",
              "pkg": "formidable",
              "severity": "LOW",
              "title": "Formidable relies on hexoid to prevent guessing of filenames for untrusted executable content"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-33987",
              "pkg": "got",
              "severity": "MODERATE",
              "title": "Got allows a redirect to a UNIX socket"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-26144",
              "pkg": "graphql",
              "severity": "MODERATE",
              "title": "graphql Uncontrolled Resource Consumption vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-48913",
              "pkg": "hono",
              "severity": "MODERATE",
              "title": "Hono allows bypass of CSRF Middleware by a request without Content-Type header."
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-59139",
              "pkg": "hono",
              "severity": "MODERATE",
              "title": "Hono has Body Limit Middleware Bypass"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-9910",
              "pkg": "jsondiffpatch",
              "severity": "LOW",
              "title": "jsondiffpatch is vulnerable to Cross-site Scripting (XSS) via HtmlFormatter::nodeBegin"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-21534",
              "pkg": "jsonpath-plus",
              "severity": "CRITICAL",
              "title": "JSONPath Plus Remote Code Execution (RCE) Vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-1302",
              "pkg": "jsonpath-plus",
              "severity": "HIGH",
              "title": "JSONPath Plus allows Remote Code Execution"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-55565",
              "pkg": "nanoid",
              "severity": "MODERATE",
              "title": "Predictable results in nanoid generation when given non-integer values"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-7339",
              "pkg": "on-headers",
              "severity": "LOW",
              "title": "on-headers is vulnerable to http response header manipulation"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-52798",
              "pkg": "path-to-regexp",
              "severity": "HIGH",
              "title": "path-to-regexp contains a ReDoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2021-23382",
              "pkg": "postcss",
              "severity": "MODERATE",
              "title": "Regular Expression Denial of Service in postcss"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-44270",
              "pkg": "postcss",
              "severity": "MODERATE",
              "title": "PostCSS line return parsing error"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2021-23382",
              "pkg": "postcss",
              "severity": "MODERATE",
              "title": "Regular Expression Denial of Service in postcss"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2021-23368",
              "pkg": "postcss",
              "severity": "MODERATE",
              "title": "Regular Expression Denial of Service in postcss"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-44270",
              "pkg": "postcss",
              "severity": "MODERATE",
              "title": "PostCSS line return parsing error"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-44270",
              "pkg": "postcss",
              "severity": "MODERATE",
              "title": "PostCSS line return parsing error"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-44270",
              "pkg": "postcss",
              "severity": "MODERATE",
              "title": "PostCSS line return parsing error"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53382",
              "pkg": "prismjs",
              "severity": "MODERATE",
              "title": "PrismJS DOM Clobbering vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-28155",
              "pkg": "request",
              "severity": "MODERATE",
              "title": "Server-Side Request Forgery in Request"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47068",
              "pkg": "rollup",
              "severity": "HIGH",
              "title": "DOM Clobbering Gadget found in rollup bundled scripts that leads to XSS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47068",
              "pkg": "rollup",
              "severity": "HIGH",
              "title": "DOM Clobbering Gadget found in rollup bundled scripts that leads to XSS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-25883",
              "pkg": "semver",
              "severity": "HIGH",
              "title": "semver vulnerable to Regular Expression Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-43799",
              "pkg": "send",
              "severity": "LOW",
              "title": "send vulnerable to template injection that can lead to XSS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-11831",
              "pkg": "serialize-javascript",
              "severity": "MODERATE",
              "title": "Cross-site Scripting (XSS) in serialize-javascript"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-28863",
              "pkg": "tar",
              "severity": "MODERATE",
              "title": "Denial of service while parsing a tar file due to lack of folders count validation"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-26136",
              "pkg": "tough-cookie",
              "severity": "MODERATE",
              "title": "tough-cookie Prototype Pollution vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22150",
              "pkg": "undici",
              "severity": "MODERATE",
              "title": "Use of Insufficiently Random Values in undici"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47279",
              "pkg": "undici",
              "severity": "LOW",
              "title": "undici Denial of Service attack via bad certificate data"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-26115",
              "pkg": "word-wrap",
              "severity": "MODERATE",
              "title": "word-wrap vulnerable to Regular Expression Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-37890",
              "pkg": "ws",
              "severity": "HIGH",
              "title": "ws affected by a DoS when handling a request with many HTTP headers"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-37890",
              "pkg": "ws",
              "severity": "HIGH",
              "title": "ws affected by a DoS when handling a request with many HTTP headers"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-37890",
              "pkg": "ws",
              "severity": "HIGH",
              "title": "ws affected by a DoS when handling a request with many HTTP headers"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-37890",
              "pkg": "ws",
              "severity": "HIGH",
              "title": "ws affected by a DoS when handling a request with many HTTP headers"
            }
          ]
        },
        "outdated": {
          "count": 3,
          "packages": {
            "@changesets/cli": {
              "dependent": "trigger.dev",
              "latest": "2.29.7",
              "wanted": "2.26.2"
            },
            "@remix-run/changelog-github": {
              "dependent": "trigger.dev",
              "latest": "0.0.5",
              "wanted": "0.0.5"
            },
            "node-fetch": {
              "dependent": "trigger.dev",
              "latest": "3.3.2",
              "wanted": "2.6.13"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 5
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "mcp-for-beginners",
      "owner": "microsoft",
      "fullName": "microsoft/mcp-for-beginners",
      "url": "https://github.com/microsoft/mcp-for-beginners",
      "stars": 10722,
      "description": "This open-source curriculum introduces the fundamentals of Model Context Protocol (MCP) through real-world, cross-language examples in .NET, Java, TypeScript, JavaScript, Rust and Python. Designed for developers, it focuses on practical techniques for building modular, scalable, and secure AI workflows from session setup to service orchestration.",
      "language": "Jupyter Notebook",
      "updatedAt": "2025-09-18T17:08:48Z",
      "scanDate": "2025-09-19T02:16:12.022844+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "fastapi_mcp",
      "owner": "tadata-org",
      "fullName": "tadata-org/fastapi_mcp",
      "url": "https://github.com/tadata-org/fastapi_mcp",
      "stars": 10415,
      "description": "Expose your FastAPI endpoints as Model Context Protocol (MCP) tools, with Auth!",
      "language": "Python",
      "updatedAt": "2025-09-18T16:20:40Z",
      "scanDate": "2025-09-19T02:17:45.032467+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "nginx-ui",
      "owner": "0xJacky",
      "fullName": "0xJacky/nginx-ui",
      "url": "https://github.com/0xJacky/nginx-ui",
      "stars": 9545,
      "description": "Yet another WebUI for Nginx",
      "language": "Go",
      "updatedAt": "2025-09-18T14:10:47Z",
      "scanDate": "2025-09-19T02:17:46.881208+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": true,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "XHS-Downloader",
      "owner": "JoeanAmier",
      "fullName": "JoeanAmier/XHS-Downloader",
      "url": "https://github.com/JoeanAmier/XHS-Downloader",
      "stars": 8724,
      "description": "小红书（XiaoHongShu、RedNote）链接提取/作品采集工具：提取账号发布、收藏、点赞、专辑作品链接；提取搜索结果作品、用户链接；采集小红书作品信息；提取小红书作品下载地址；下载小红书无水印作品文件",
      "language": "Python",
      "updatedAt": "2025-09-18T09:45:34Z",
      "scanDate": "2025-09-19T02:17:54.132201+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "claude-flow",
      "owner": "ruvnet",
      "fullName": "ruvnet/claude-flow",
      "url": "https://github.com/ruvnet/claude-flow",
      "stars": 7973,
      "description": "🌊 The leading agent orchestration platform for Claude. Deploy intelligent multi-agent swarms, coordinate autonomous workflows, and build conversational AI systems. Features    enterprise-grade architecture, distributed swarm intelligence, RAG integration, and native Claude Code support via MCP protocol. Ranked #1 in agent-based frameworks.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:38:50Z",
      "scanDate": "2025-09-19T02:17:56.137037+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 3,
          "moderate": 0,
          "total": 3
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 2,
          "medium": 0,
          "total": 2,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            }
          ]
        },
        "outdated": {
          "count": 22,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "claude-flow",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "@types/better-sqlite3": {
              "dependent": "claude-flow",
              "latest": "7.6.13",
              "wanted": "7.6.13"
            },
            "better-sqlite3": {
              "dependent": "claude-flow",
              "latest": "12.2.0",
              "wanted": "12.2.0"
            },
            "blessed": {
              "dependent": "claude-flow",
              "latest": "0.1.81",
              "wanted": "0.1.81"
            },
            "chalk": {
              "dependent": "claude-flow",
              "latest": "5.6.2",
              "wanted": "4.1.2"
            },
            "cli-table3": {
              "dependent": "claude-flow",
              "latest": "0.6.5",
              "wanted": "0.6.5"
            },
            "commander": {
              "dependent": "claude-flow",
              "latest": "14.0.1",
              "wanted": "11.1.0"
            },
            "cors": {
              "dependent": "claude-flow",
              "latest": "2.8.5",
              "wanted": "2.8.5"
            },
            "diskusage": {
              "dependent": "claude-flow",
              "latest": "1.2.0",
              "wanted": "1.2.0"
            },
            "figlet": {
              "dependent": "claude-flow",
              "latest": "1.9.3",
              "wanted": "1.9.3"
            },
            "fs-extra": {
              "dependent": "claude-flow",
              "latest": "11.3.2",
              "wanted": "11.3.2"
            },
            "glob": {
              "dependent": "claude-flow",
              "latest": "11.0.3",
              "wanted": "11.0.3"
            },
            "gradient-string": {
              "dependent": "claude-flow",
              "latest": "3.0.0",
              "wanted": "3.0.0"
            },
            "helmet": {
              "dependent": "claude-flow",
              "latest": "8.1.0",
              "wanted": "7.2.0"
            },
            "inquirer": {
              "dependent": "claude-flow",
              "latest": "12.9.6",
              "wanted": "9.3.8"
            },
            "nanoid": {
              "dependent": "claude-flow",
              "latest": "5.1.5",
              "wanted": "5.1.5"
            },
            "node-pty": {
              "dependent": "claude-flow",
              "latest": "1.0.0",
              "wanted": "1.0.0"
            },
            "ora": {
              "dependent": "claude-flow",
              "latest": "9.0.0",
              "wanted": "7.0.1"
            },
            "p-queue": {
              "dependent": "claude-flow",
              "latest": "8.1.1",
              "wanted": "8.1.1"
            },
            "ruv-swarm": {
              "dependent": "claude-flow",
              "latest": "1.0.20",
              "wanted": "1.0.20"
            },
            "ws": {
              "dependent": "claude-flow",
              "latest": "8.18.3",
              "wanted": "8.18.3"
            },
            "yaml": {
              "dependent": "claude-flow",
              "latest": "2.8.1",
              "wanted": "2.8.1"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": true,
          "score": 5
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "OpenMetadata",
      "owner": "open-metadata",
      "fullName": "open-metadata/OpenMetadata",
      "url": "https://github.com/open-metadata/OpenMetadata",
      "stars": 7544,
      "description": "OpenMetadata is a unified metadata platform for data discovery, data observability, and data governance powered by a central metadata repository, in-depth column level lineage, and seamless team collaboration.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:45:18Z",
      "scanDate": "2025-09-19T02:18:25.475107+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "outdated": {
          "count": 0,
          "packages": {}
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": true,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "Scrapling",
      "owner": "D4Vinci",
      "fullName": "D4Vinci/Scrapling",
      "url": "https://github.com/D4Vinci/Scrapling",
      "stars": 7318,
      "description": "🕷️ An undetectable, powerful, flexible, high-performance Python library to make Web Scraping Easy and Effortless as it should be!",
      "language": "Python",
      "updatedAt": "2025-09-18T17:01:09Z",
      "scanDate": "2025-09-19T02:18:41.969157+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "lamda",
      "owner": "firerpa",
      "fullName": "firerpa/lamda",
      "url": "https://github.com/firerpa/lamda",
      "stars": 7273,
      "description": " The most powerful Android RPA agent framework, next generation of mobile automation robots.",
      "language": "Python",
      "updatedAt": "2025-09-18T13:36:29Z",
      "scanDate": "2025-09-19T02:18:43.912199+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 1
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "n8n-mcp",
      "owner": "czlonkowski",
      "fullName": "czlonkowski/n8n-mcp",
      "url": "https://github.com/czlonkowski/n8n-mcp",
      "stars": 6977,
      "description": "A MCP for Claude Desktop / Claude Code / Windsurf / Cursor to build n8n workflows for you ",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:34:01Z",
      "scanDate": "2025-09-19T02:18:45.985991+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 15,
          "high": 7,
          "info": 0,
          "low": 0,
          "moderate": 6,
          "total": 28
        },
        "osv": {
          "critical": 1,
          "high": 2,
          "low": 0,
          "medium": 0,
          "total": 5,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2024-35255",
              "pkg": "@azure/identity",
              "severity": "MODERATE",
              "title": "Azure Identity Libraries and Microsoft Authentication Library Elevation of Privilege Vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-37168",
              "pkg": "@grpc/grpc-js",
              "severity": "MODERATE",
              "title": "@grpc/grpc-js can allocate memory for incoming messages well above configured limits"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-7783",
              "pkg": "form-data",
              "severity": "CRITICAL",
              "title": "form-data uses unsafe random function in form-data for choosing boundary"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-25883",
              "pkg": "semver",
              "severity": "HIGH",
              "title": "semver vulnerable to Regular Expression Denial of Service"
            }
          ]
        },
        "outdated": {
          "count": 14,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "n8n-mcp",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "@n8n/n8n-nodes-langchain": {
              "dependent": "n8n-mcp",
              "latest": "0.3.0",
              "wanted": "1.111.1"
            },
            "@rollup/rollup-darwin-arm64": {
              "dependent": "n8n-mcp",
              "latest": "4.50.2",
              "wanted": "4.50.2"
            },
            "@rollup/rollup-linux-x64-gnu": {
              "dependent": "n8n-mcp",
              "latest": "4.50.2",
              "wanted": "4.50.2"
            },
            "better-sqlite3": {
              "dependent": "n8n-mcp",
              "latest": "12.2.0",
              "wanted": "11.10.0"
            },
            "dotenv": {
              "dependent": "n8n-mcp",
              "latest": "17.2.2",
              "wanted": "16.6.1"
            },
            "express": {
              "dependent": "n8n-mcp",
              "latest": "5.1.0",
              "wanted": "5.1.0"
            },
            "n8n": {
              "dependent": "n8n-mcp",
              "latest": "1.111.0",
              "wanted": "1.111.0"
            },
            "n8n-core": {
              "dependent": "n8n-mcp",
              "latest": "1.14.1",
              "wanted": "1.111.0"
            },
            "n8n-workflow": {
              "dependent": "n8n-mcp",
              "latest": "1.82.0",
              "wanted": "1.109.0"
            },
            "openai": {
              "dependent": "n8n-mcp",
              "latest": "5.21.0",
              "wanted": "4.104.0"
            },
            "sql.js": {
              "dependent": "n8n-mcp",
              "latest": "1.13.0",
              "wanted": "1.13.0"
            },
            "uuid": {
              "dependent": "n8n-mcp",
              "latest": "13.0.0",
              "wanted": "10.0.0"
            },
            "zod": {
              "dependent": "n8n-mcp",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 5
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "xiaozhi-esp32-server",
      "owner": "xinnan-tech",
      "fullName": "xinnan-tech/xiaozhi-esp32-server",
      "url": "https://github.com/xinnan-tech/xiaozhi-esp32-server",
      "stars": 6717,
      "description": "本项目为xiaozhi-esp32提供后端服务，帮助您快速搭建ESP32设备控制服务器。Backend service for xiaozhi-esp32, helps you quickly build an ESP32 device control server.",
      "language": "Python",
      "updatedAt": "2025-09-18T11:09:00Z",
      "scanDate": "2025-09-19T02:19:28.577959+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "browser-tools-mcp",
      "owner": "AgentDeskAI",
      "fullName": "AgentDeskAI/browser-tools-mcp",
      "url": "https://github.com/AgentDeskAI/browser-tools-mcp",
      "stars": 6541,
      "description": "Monitor browser logs directly from Cursor and other MCP compatible IDEs.",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T16:40:22Z",
      "scanDate": "2025-09-19T02:19:35.886126+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcp",
      "owner": "awslabs",
      "fullName": "awslabs/mcp",
      "url": "https://github.com/awslabs/mcp",
      "stars": 6380,
      "description": "AWS MCP Servers — helping you get the most out of AWS, wherever you use MCP.",
      "language": "Python",
      "updatedAt": "2025-09-18T15:49:56Z",
      "scanDate": "2025-09-19T02:19:37.187432+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": true,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": true,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "firecrawl-mcp-server",
      "owner": "firecrawl",
      "fullName": "firecrawl/firecrawl-mcp-server",
      "url": "https://github.com/firecrawl/firecrawl-mcp-server",
      "stars": 4541,
      "description": "🔥 Official Firecrawl MCP Server - Adds powerful web scraping and search to Cursor, Claude and any other LLM clients.",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T13:41:53Z",
      "scanDate": "2025-09-19T02:19:42.826705+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 1,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 1
        },
        "osv": {
          "critical": 0,
          "high": 1,
          "low": 0,
          "medium": 0,
          "total": 1,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            }
          ]
        },
        "outdated": {
          "count": 5,
          "packages": {
            "@mendable/firecrawl-js": {
              "dependent": "firecrawl-mcp-server",
              "latest": "4.3.5",
              "wanted": "4.3.5"
            },
            "dotenv": {
              "dependent": "firecrawl-mcp-server",
              "latest": "17.2.2",
              "wanted": "17.2.2"
            },
            "firecrawl-fastmcp": {
              "dependent": "firecrawl-mcp-server",
              "latest": "1.0.0",
              "wanted": "1.0.2"
            },
            "typescript": {
              "dependent": "firecrawl-mcp-server",
              "latest": "5.9.2",
              "wanted": "5.9.2"
            },
            "zod": {
              "dependent": "firecrawl-mcp-server",
              "latest": "4.1.9",
              "wanted": "4.1.9"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 88,
      "errors": []
    },
    {
      "name": "Viper",
      "owner": "FunnyWolf",
      "fullName": "FunnyWolf/Viper",
      "url": "https://github.com/FunnyWolf/Viper",
      "stars": 4528,
      "description": "Adversary simulation and Red teaming platform with AI",
      "language": "",
      "updatedAt": "2025-09-18T15:05:43Z",
      "scanDate": "2025-09-19T02:19:48.250099+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "outdated": {
          "count": 3,
          "packages": {
            "@paddle/paddle-js": {
              "dependent": "Viper",
              "latest": "1.4.2",
              "wanted": "1.4.2"
            },
            "@vercel/analytics": {
              "dependent": "Viper",
              "latest": "1.5.0",
              "wanted": "1.5.0"
            },
            "@vercel/speed-insights": {
              "dependent": "Viper",
              "latest": "1.2.0",
              "wanted": "1.2.0"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 1
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "Awesome-MCP-ZH",
      "owner": "yzfly",
      "fullName": "yzfly/Awesome-MCP-ZH",
      "url": "https://github.com/yzfly/Awesome-MCP-ZH",
      "stars": 4329,
      "description": "MCP 资源精选， MCP指南，Claude MCP，MCP Servers, MCP Clients",
      "language": "",
      "updatedAt": "2025-09-18T15:02:53Z",
      "scanDate": "2025-09-19T02:19:55.838859+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcp",
      "owner": "BrowserMCP",
      "fullName": "BrowserMCP/mcp",
      "url": "https://github.com/BrowserMCP/mcp",
      "stars": 4290,
      "description": "Browser MCP is a Model Context Provider (MCP) server that allows AI applications to control your browser",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:48:00Z",
      "scanDate": "2025-09-19T02:19:57.339946+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "outdated": {
          "count": 5,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "mcp",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "commander": {
              "dependent": "mcp",
              "latest": "14.0.1",
              "wanted": "13.1.0"
            },
            "ws": {
              "dependent": "mcp",
              "latest": "8.18.3",
              "wanted": "8.18.3"
            },
            "zod": {
              "dependent": "mcp",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            },
            "zod-to-json-schema": {
              "dependent": "mcp",
              "latest": "3.24.6",
              "wanted": "3.24.6"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "httprunner",
      "owner": "httprunner",
      "fullName": "httprunner/httprunner",
      "url": "https://github.com/httprunner/httprunner",
      "stars": 4190,
      "description": "HttpRunner 是一款开源的 API/UI 测试框架，简单易用，功能强大，具有丰富的插件化机制和高度的可扩展能力。",
      "language": "Go",
      "updatedAt": "2025-09-17T07:39:20Z",
      "scanDate": "2025-09-19T02:19:59.073446+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 2,
          "low": 0,
          "medium": 14,
          "total": 18,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-30153",
              "pkg": "github.com/getkin/kin-openapi",
              "severity": "HIGH",
              "title": "Improper Handling of Highly Compressed Data (Data Amplification) in github.com/getkin/kin-openapi/openapi3filter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-30153",
              "pkg": "github.com/getkin/kin-openapi",
              "severity": "MEDIUM",
              "title": "Improper Handling of Highly Compressed Data (Data Amplification) in github.com/getkin/kin-openapi/openapi3filter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49295",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MODERATE",
              "title": "quic-go's path validation mechanism can be exploited to cause denial of service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49295",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MEDIUM",
              "title": "Denial of service via path validation in github.com/quic-go/quic-go"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-22189",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "HIGH",
              "title": "QUIC's Connection ID Mechanism vulnerable to Memory Exhaustion Attack"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-22189",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MEDIUM",
              "title": "Denial of service via connection starvation in github.com/quic-go/quic-go"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53259",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MODERATE",
              "title": "quic-go affected by an ICMP Packet Too Large Injection Attack on Linux"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53259",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MEDIUM",
              "title": "ICMP Packet Too Large Injection Attack on Linux in github.com/quic-go/quic-go"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34155",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in all Parse functions in go/parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34156",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in Decoder.Decode in encoding/gob"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34158",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in Parse in go/build/constraint"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45341",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of IPv6 zone IDs can bypass URI name constraints in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45336",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers incorrectly sent after cross-domain redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22866",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 18,
      "errors": []
    },
    {
      "name": "deep-research",
      "owner": "u14app",
      "fullName": "u14app/deep-research",
      "url": "https://github.com/u14app/deep-research",
      "stars": 4040,
      "description": "Use any LLMs (Large Language Models) for Deep Research. Support SSE API and MCP server.",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T16:47:02Z",
      "scanDate": "2025-09-19T02:20:11.799687+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 2,
          "medium": 0,
          "total": 7,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-xffm-g5w8-qvg7",
              "pkg": "@eslint/plugin-kit",
              "severity": "LOW",
              "title": "@eslint/plugin-kit is vulnerable to Regular Expression Denial of Service attacks through ConfigCommentParser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-9910",
              "pkg": "jsondiffpatch",
              "severity": "LOW",
              "title": "jsondiffpatch is vulnerable to Cross-site Scripting (XSS) via HtmlFormatter::nodeBegin"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54881",
              "pkg": "mermaid",
              "severity": "MODERATE",
              "title": "Mermaid improperly sanitizes sequence diagram labels leading to XSS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54880",
              "pkg": "mermaid",
              "severity": "MODERATE",
              "title": "Mermaid does not properly sanitize architecture diagram iconText leading to XSS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57752",
              "pkg": "next",
              "severity": "MODERATE",
              "title": "Next.js Affected by Cache Key Confusion for Image Optimization API Routes"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-55173",
              "pkg": "next",
              "severity": "MODERATE",
              "title": "Next.js Content Injection Vulnerability for Image Optimization"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57822",
              "pkg": "next",
              "severity": "MODERATE",
              "title": "Next.js Improper Middleware Redirect Handling Leads to SSRF"
            }
          ]
        },
        "outdated": {
          "count": 71,
          "packages": {
            "@ai-sdk/anthropic": {
              "dependent": "deep-research",
              "latest": "2.0.17",
              "wanted": "1.2.12"
            },
            "@ai-sdk/azure": {
              "dependent": "deep-research",
              "latest": "2.0.32",
              "wanted": "1.3.25"
            },
            "@ai-sdk/deepseek": {
              "dependent": "deep-research",
              "latest": "1.0.18",
              "wanted": "0.2.16"
            },
            "@ai-sdk/google": {
              "dependent": "deep-research",
              "latest": "2.0.14",
              "wanted": "1.2.22"
            },
            "@ai-sdk/google-vertex": {
              "dependent": "deep-research",
              "latest": "3.0.27",
              "wanted": "2.2.27"
            },
            "@ai-sdk/mistral": {
              "dependent": "deep-research",
              "latest": "2.0.14",
              "wanted": "1.2.8"
            },
            "@ai-sdk/openai": {
              "dependent": "deep-research",
              "latest": "2.0.32",
              "wanted": "1.3.24"
            },
            "@ai-sdk/openai-compatible": {
              "dependent": "deep-research",
              "latest": "1.0.18",
              "wanted": "0.2.16"
            },
            "@ai-sdk/ui-utils": {
              "dependent": "deep-research",
              "latest": "1.2.11",
              "wanted": "1.2.11"
            },
            "@ai-sdk/xai": {
              "dependent": "deep-research",
              "latest": "2.0.20",
              "wanted": "1.2.18"
            },
            "@hookform/resolvers": {
              "dependent": "deep-research",
              "latest": "5.2.2",
              "wanted": "4.1.3"
            },
            "@openrouter/ai-sdk-provider": {
              "dependent": "deep-research",
              "latest": "1.2.0",
              "wanted": "0.4.6"
            },
            "@radix-ui/react-accordion": {
              "dependent": "deep-research",
              "latest": "1.2.12",
              "wanted": "1.2.12"
            },
            "@radix-ui/react-dialog": {
              "dependent": "deep-research",
              "latest": "1.1.15",
              "wanted": "1.1.15"
            },
            "@radix-ui/react-dropdown-menu": {
              "dependent": "deep-research",
              "latest": "2.1.16",
              "wanted": "2.1.16"
            },
            "@radix-ui/react-label": {
              "dependent": "deep-research",
              "latest": "2.1.7",
              "wanted": "2.1.7"
            },
            "@radix-ui/react-popover": {
              "dependent": "deep-research",
              "latest": "1.1.15",
              "wanted": "1.1.15"
            },
            "@radix-ui/react-scroll-area": {
              "dependent": "deep-research",
              "latest": "1.2.10",
              "wanted": "1.2.10"
            },
            "@radix-ui/react-select": {
              "dependent": "deep-research",
              "latest": "2.2.6",
              "wanted": "2.2.6"
            },
            "@radix-ui/react-separator": {
              "dependent": "deep-research",
              "latest": "1.1.7",
              "wanted": "1.1.7"
            },
            "@radix-ui/react-slider": {
              "dependent": "deep-research",
              "latest": "1.3.6",
              "wanted": "1.3.6"
            },
            "@radix-ui/react-slot": {
              "dependent": "deep-research",
              "latest": "1.2.3",
              "wanted": "1.2.3"
            },
            "@radix-ui/react-tabs": {
              "dependent": "deep-research",
              "latest": "1.1.13",
              "wanted": "1.1.13"
            },
            "@radix-ui/react-tooltip": {
              "dependent": "deep-research",
              "latest": "1.2.8",
              "wanted": "1.2.8"
            },
            "@serwist/next": {
              "dependent": "deep-research",
              "latest": "9.2.1",
              "wanted": "9.2.1"
            },
            "@xiangfa/mdeditor": {
              "dependent": "deep-research",
              "latest": "0.2.3",
              "wanted": "0.2.3"
            },
            "@zip.js/zip.js": {
              "dependent": "deep-research",
              "latest": "2.8.2",
              "wanted": "2.8.2"
            },
            "ai": {
              "dependent": "deep-research",
              "latest": "5.0.45",
              "wanted": "4.3.19"
            },
            "class-variance-authority": {
              "dependent": "deep-research",
              "latest": "0.7.1",
              "wanted": "0.7.1"
            },
            "clsx": {
              "dependent": "deep-research",
              "latest": "2.1.1",
              "wanted": "2.1.1"
            },
            "copy-to-clipboard": {
              "dependent": "deep-research",
              "latest": "3.3.3",
              "wanted": "3.3.3"
            },
            "dayjs": {
              "dependent": "deep-research",
              "latest": "1.11.18",
              "wanted": "1.11.18"
            },
            "file-saver": {
              "dependent": "deep-research",
              "latest": "2.0.5",
              "wanted": "2.0.5"
            },
            "fuse.js": {
              "dependent": "deep-research",
              "latest": "7.1.0",
              "wanted": "7.1.0"
            },
            "i18next": {
              "dependent": "deep-research",
              "latest": "25.5.2",
              "wanted": "24.2.3"
            },
            "i18next-browser-languagedetector": {
              "dependent": "deep-research",
              "latest": "8.2.0",
              "wanted": "8.2.0"
            },
            "i18next-resources-to-backend": {
              "dependent": "deep-research",
              "latest": "1.2.1",
              "wanted": "1.2.1"
            },
            "katex": {
              "dependent": "deep-research",
              "latest": "0.16.22",
              "wanted": "0.16.22"
            },
            "localforage": {
              "dependent": "deep-research",
              "latest": "1.10.0",
              "wanted": "1.10.0"
            },
            "lucide-react": {
              "dependent": "deep-research",
              "latest": "0.544.0",
              "wanted": "0.475.0"
            },
            "marked": {
              "dependent": "deep-research",
              "latest": "16.3.0",
              "wanted": "15.0.12"
            },
            "mermaid": {
              "dependent": "deep-research",
              "latest": "11.12.0",
              "wanted": "11.12.0"
            },
            "nanoid": {
              "dependent": "deep-research",
              "latest": "5.1.5",
              "wanted": "5.1.5"
            },
            "next": {
              "dependent": "deep-research",
              "latest": "15.5.3",
              "wanted": "15.5.3"
            },
            "next-themes": {
              "dependent": "deep-research",
              "latest": "0.4.6",
              "wanted": "0.4.6"
            },
            "ollama-ai-provider": {
              "dependent": "deep-research",
              "latest": "1.2.0",
              "wanted": "1.2.0"
            },
            "p-limit": {
              "dependent": "deep-research",
              "latest": "7.1.1",
              "wanted": "6.2.0"
            },
            "pdfjs-dist": {
              "dependent": "deep-research",
              "latest": "5.4.149",
              "wanted": "5.1.91"
            },
            "radash": {
              "dependent": "deep-research",
              "latest": "12.1.1",
              "wanted": "12.1.1"
            },
            "react": {
              "dependent": "deep-research",
              "latest": "19.1.1",
              "wanted": "19.1.1"
            },
            "react-dom": {
              "dependent": "deep-research",
              "latest": "19.1.1",
              "wanted": "19.1.1"
            },
            "react-hook-form": {
              "dependent": "deep-research",
              "latest": "7.62.0",
              "wanted": "7.62.0"
            },
            "react-i18next": {
              "dependent": "deep-research",
              "latest": "15.7.3",
              "wanted": "15.7.3"
            },
            "react-markdown": {
              "dependent": "deep-research",
              "latest": "10.1.0",
              "wanted": "10.1.0"
            },
            "react-resizable-panels": {
              "dependent": "deep-research",
              "latest": "3.0.6",
              "wanted": "3.0.6"
            },
            "react-use-pwa-install": {
              "dependent": "deep-research",
              "latest": "1.0.3",
              "wanted": "1.0.3"
            },
            "react-zoom-pan-pinch": {
              "dependent": "deep-research",
              "latest": "3.7.0",
              "wanted": "3.7.0"
            },
            "rehype-highlight": {
              "dependent": "deep-research",
              "latest": "7.0.2",
              "wanted": "7.0.2"
            },
            "rehype-katex": {
              "dependent": "deep-research",
              "latest": "7.0.1",
              "wanted": "7.0.1"
            },
            "rehype-raw": {
              "dependent": "deep-research",
              "latest": "7.0.0",
              "wanted": "7.0.0"
            },
            "remark-breaks": {
              "dependent": "deep-research",
              "latest": "4.0.0",
              "wanted": "4.0.0"
            },
            "remark-gfm": {
              "dependent": "deep-research",
              "latest": "4.0.1",
              "wanted": "4.0.1"
            },
            "remark-math": {
              "dependent": "deep-research",
              "latest": "6.0.0",
              "wanted": "6.0.0"
            },
            "sonner": {
              "dependent": "deep-research",
              "latest": "2.0.7",
              "wanted": "2.0.7"
            },
            "tailwind-merge": {
              "dependent": "deep-research",
              "latest": "3.3.1",
              "wanted": "3.3.1"
            },
            "tailwindcss-animate": {
              "dependent": "deep-research",
              "latest": "1.0.7",
              "wanted": "1.0.7"
            },
            "ts-md5": {
              "dependent": "deep-research",
              "latest": "2.0.1",
              "wanted": "1.3.1"
            },
            "unist-util-visit": {
              "dependent": "deep-research",
              "latest": "5.0.0",
              "wanted": "5.0.0"
            },
            "zod": {
              "dependent": "deep-research",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            },
            "zod-to-json-schema": {
              "dependent": "deep-research",
              "latest": "3.24.6",
              "wanted": "3.24.6"
            },
            "zustand": {
              "dependent": "deep-research",
              "latest": "5.0.8",
              "wanted": "5.0.8"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "klavis",
      "owner": "Klavis-AI",
      "fullName": "Klavis-AI/klavis",
      "url": "https://github.com/Klavis-AI/klavis",
      "stars": 4024,
      "description": "Klavis AI (YC X25):  Open Source MCP integration for AI applications",
      "language": "Python",
      "updatedAt": "2025-09-18T08:23:55Z",
      "scanDate": "2025-09-19T02:20:25.494081+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "ENScan_GO",
      "owner": "wgpsec",
      "fullName": "wgpsec/ENScan_GO",
      "url": "https://github.com/wgpsec/ENScan_GO",
      "stars": 3914,
      "description": "一款基于各大企业信息API的工具，解决在遇到的各种针对国内企业信息收集难题。一键收集控股公司ICP备案、APP、小程序、微信公众号等信息聚合导出。支持MCP接入",
      "language": "Go",
      "updatedAt": "2025-09-18T13:00:45Z",
      "scanDate": "2025-09-19T02:20:29.661662+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 1,
          "high": 3,
          "low": 1,
          "medium": 17,
          "total": 28,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-8556",
              "pkg": "github.com/cloudflare/circl",
              "severity": "LOW",
              "title": "CIRCL-Fourq: Missing and wrong validation can lead to incorrect results"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-8556",
              "pkg": "github.com/cloudflare/circl",
              "severity": "MEDIUM",
              "title": "CIRCL-Fourq: Missing and wrong validation can lead to incorrect results in github.com/cloudflare/circl"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-3445",
              "pkg": "github.com/mholt/archiver/v3",
              "severity": "HIGH",
              "title": "mholt/archiver Vulnerable to Path Traversal via Crafted ZIP File"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-0406",
              "pkg": "github.com/mholt/archiver/v3",
              "severity": "MODERATE",
              "title": "Archiver Path Traversal vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-0406",
              "pkg": "github.com/mholt/archiver/v3",
              "severity": "MEDIUM",
              "title": "Archiver Path Traversal vulnerability in github.com/mholt/archiver"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-3445",
              "pkg": "github.com/mholt/archiver/v3",
              "severity": "MEDIUM",
              "title": "Vulnerable to Path Traversal via Crafted ZIP File in github.com/mholt/archiver"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-22189",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "HIGH",
              "title": "QUIC's Connection ID Mechanism vulnerable to Memory Exhaustion Attack"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-22189",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MEDIUM",
              "title": "Denial of service via connection starvation in github.com/quic-go/quic-go"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53259",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MODERATE",
              "title": "quic-go affected by an ICMP Packet Too Large Injection Attack on Linux"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53259",
              "pkg": "github.com/quic-go/quic-go",
              "severity": "MEDIUM",
              "title": "ICMP Packet Too Large Injection Attack on Linux in github.com/quic-go/quic-go"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-pmc3-p9hx-jq96",
              "pkg": "github.com/refraction-networking/utls",
              "severity": "MODERATE",
              "title": "uTLS ServerHellos are accepted without checking TLS 1.3 downgrade canaries"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-pmc3-p9hx-jq96",
              "pkg": "github.com/refraction-networking/utls",
              "severity": "MEDIUM",
              "title": "ServerHellos are accepted without checking TLS 1.3 downgrade canaries in github.com/refraction-networking/utls"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58058",
              "pkg": "github.com/ulikunitz/xz",
              "severity": "MODERATE",
              "title": "github.com/ulikunitz/xz leaks memory when decoding a corrupted multiple LZMA archives"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58058",
              "pkg": "github.com/ulikunitz/xz",
              "severity": "MEDIUM",
              "title": "Memory leaks when decoding a corrupted multiple LZMA archives in github.com/ulikunitz/xz"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45337",
              "pkg": "golang.org/x/crypto",
              "severity": "CRITICAL",
              "title": "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45337",
              "pkg": "golang.org/x/crypto",
              "severity": "MEDIUM",
              "title": "Misuse of connection.serverAuthenticate may cause authorization bypass in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22869",
              "pkg": "golang.org/x/crypto",
              "severity": "HIGH",
              "title": "golang.org/x/crypto Vulnerable to Denial of Service (DoS) via Slow or Incomplete Key Exchange"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22869",
              "pkg": "golang.org/x/crypto",
              "severity": "MEDIUM",
              "title": "Potential denial of service in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45338",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "Non-linear parsing of case-insensitive content in golang.org/x/net/html"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22870",
              "pkg": "golang.org/x/net",
              "severity": "MODERATE",
              "title": "HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22870",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22872",
              "pkg": "golang.org/x/net",
              "severity": "MODERATE",
              "title": "golang.org/x/net vulnerable to Cross-site Scripting"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22872",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "Incorrect Neutralization of Input During Web Page Generation in x/net in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22874",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of ExtKeyUsageAny disables policy validation in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": true,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "ida-pro-mcp",
      "owner": "mrexodia",
      "fullName": "mrexodia/ida-pro-mcp",
      "url": "https://github.com/mrexodia/ida-pro-mcp",
      "stars": 3660,
      "description": "MCP Server for IDA Pro.",
      "language": "Python",
      "updatedAt": "2025-09-18T16:27:00Z",
      "scanDate": "2025-09-19T02:20:37.871524+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "xiaohongshu-mcp",
      "owner": "xpzouying",
      "fullName": "xpzouying/xiaohongshu-mcp",
      "url": "https://github.com/xpzouying/xiaohongshu-mcp",
      "stars": 3519,
      "description": "MCP for xiaohongshu.com",
      "language": "Go",
      "updatedAt": "2025-09-18T17:10:30Z",
      "scanDate": "2025-09-19T02:20:39.122011+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 1,
          "high": 1,
          "low": 0,
          "medium": 10,
          "total": 14,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2024-45337",
              "pkg": "golang.org/x/crypto",
              "severity": "CRITICAL",
              "title": "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45337",
              "pkg": "golang.org/x/crypto",
              "severity": "MEDIUM",
              "title": "Misuse of connection.serverAuthenticate may cause authorization bypass in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22869",
              "pkg": "golang.org/x/crypto",
              "severity": "HIGH",
              "title": "golang.org/x/crypto Vulnerable to Denial of Service (DoS) via Slow or Incomplete Key Exchange"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22869",
              "pkg": "golang.org/x/crypto",
              "severity": "MEDIUM",
              "title": "Potential denial of service in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45338",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "Non-linear parsing of case-insensitive content in golang.org/x/net/html"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22870",
              "pkg": "golang.org/x/net",
              "severity": "MODERATE",
              "title": "HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22870",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22872",
              "pkg": "golang.org/x/net",
              "severity": "MODERATE",
              "title": "golang.org/x/net vulnerable to Cross-site Scripting"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22872",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "Incorrect Neutralization of Input During Web Page Generation in x/net in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22874",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of ExtKeyUsageAny disables policy validation in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 29,
      "errors": []
    },
    {
      "name": "mcpo",
      "owner": "open-webui",
      "fullName": "open-webui/mcpo",
      "url": "https://github.com/open-webui/mcpo",
      "stars": 3322,
      "description": "A simple, secure MCP-to-OpenAPI proxy server",
      "language": "Python",
      "updatedAt": "2025-09-18T15:25:34Z",
      "scanDate": "2025-09-19T02:20:48.334466+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "hexstrike-ai",
      "owner": "0x4m4",
      "fullName": "0x4m4/hexstrike-ai",
      "url": "https://github.com/0x4m4/hexstrike-ai",
      "stars": 3113,
      "description": "HexStrike AI MCP Agents is an advanced MCP server that lets AI agents (Claude, GPT, Copilot, etc.) autonomously run 150+ cybersecurity tools for automated pentesting, vulnerability discovery, bug bounty automation, and security research. Seamlessly bridge LLMs with real-world offensive security capabilities.",
      "language": "Python",
      "updatedAt": "2025-09-18T17:06:08Z",
      "scanDate": "2025-09-19T02:20:49.629798+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 4,
          "high": 7,
          "low": 3,
          "medium": 22,
          "total": 49,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2023-37276",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP request parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-30251",
              "pkg": "aiohttp",
              "severity": "HIGH",
              "title": "aiohttp vulnerable to Denial of Service when trying to parse malformed POST requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-27306",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp Cross-site Scripting vulnerability on index pages for static file handling"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-52304",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp allows request smuggling due to incorrect parsing of chunk extensions"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-23829",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp's HTTP parser (the python one, not llhttp) still overly lenient about separators"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53643",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": " AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-47627",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "AIOHTTP has problems in HTTP parser (the python one, not llhttp)"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-pjjw-qhg8-p2p9",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp has vulnerable dependency that is vulnerable to request smuggling"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49081",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp's ClientSession is vulnerable to CRLF injection via version"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49082",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp's ClientSession is vulnerable to CRLF injection via method"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2021-21330",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": "`aiohttp` Open Redirect vulnerability (`normalize_path_middleware` middleware)"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-47641",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": "Aiohttp has inconsistent interpretation of `Content-Length` vs. `Transfer-Encoding` differing in C and Python fallbacks"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2021-21330",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-37276",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": "aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP request parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-47627",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-47641",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49081",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49082",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-23829",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-1000656",
              "pkg": "flask",
              "severity": "HIGH",
              "title": "Flask is vulnerable to Denial of Service via incorrect encoding of JSON data"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2019-1010083",
              "pkg": "flask",
              "severity": "HIGH",
              "title": "Pallets Project Flask is vulnerable to Denial of Service via Unexpected memory usage"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-30861",
              "pkg": "flask",
              "severity": "HIGH",
              "title": "Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-1000656",
              "pkg": "flask",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2019-1010083",
              "pkg": "flask",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-30861",
              "pkg": "flask",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2021-39214",
              "pkg": "mitmproxy",
              "severity": "CRITICAL",
              "title": "Lacking Protection against HTTP Request Smuggling in mitmproxy"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-63cx-g855-hvv4",
              "pkg": "mitmproxy",
              "severity": "MODERATE",
              "title": "mitmproxy binaries embed a vulnerable python-hyper/h2 dependency"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-14505",
              "pkg": "mitmproxy",
              "severity": "CRITICAL",
              "title": "Mitmweb in mitmproxy allows DNS Rebinding attacks"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-24766",
              "pkg": "mitmproxy",
              "severity": "CRITICAL",
              "title": "Insufficient Protection against HTTP Request Smuggling in mitmproxy"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-23217",
              "pkg": "mitmproxy",
              "severity": "HIGH",
              "title": "Mitmweb API Authentication Bypass Using Proxy Server"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-14505",
              "pkg": "mitmproxy",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2021-39214",
              "pkg": "mitmproxy",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-24766",
              "pkg": "mitmproxy",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2019-18874",
              "pkg": "psutil",
              "severity": "HIGH",
              "title": "Double Free in psutil"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2019-18874",
              "pkg": "psutil",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2020-28468",
              "pkg": "pwntools",
              "severity": "CRITICAL",
              "title": "pwntools Server-Side Template Injection (SSTI) vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2020-28468",
              "pkg": "pwntools",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1830",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Exposure of Sensitive Information to an Unauthorized Actor in Requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-35195",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests `Session` object does not verify requests after making first request with verify=False"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1829",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Exposure of Sensitive Information to an Unauthorized Actor in Requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-18074",
              "pkg": "requests",
              "severity": "HIGH",
              "title": "Insufficiently Protected Credentials in Requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1829",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1830",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2015-2296",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-18074",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-32681",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-28108",
              "pkg": "selenium",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-5590",
              "pkg": "selenium",
              "severity": "MEDIUM",
              "title": ""
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": false,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 0
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "MCP-Chinese-Getting-Started-Guide",
      "owner": "liaokongVFX",
      "fullName": "liaokongVFX/MCP-Chinese-Getting-Started-Guide",
      "url": "https://github.com/liaokongVFX/MCP-Chinese-Getting-Started-Guide",
      "stars": 2895,
      "description": "Model Context Protocol(MCP) 编程极速入门",
      "language": "",
      "updatedAt": "2025-09-18T13:54:58Z",
      "scanDate": "2025-09-19T02:20:53.707664+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": false,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 0
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcp-server-chart",
      "owner": "antvis",
      "fullName": "antvis/mcp-server-chart",
      "url": "https://github.com/antvis/mcp-server-chart",
      "stars": 2801,
      "description": "🤖 A visualization mcp contains 25+ visual charts using @antvis. Using for chart generation and data analysis.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:41:35Z",
      "scanDate": "2025-09-19T02:20:55.130868+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "outdated": {
          "count": 6,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "mcp-server-chart",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "axios": {
              "dependent": "mcp-server-chart",
              "latest": "1.12.2",
              "wanted": "1.12.2"
            },
            "cors": {
              "dependent": "mcp-server-chart",
              "latest": "2.8.5",
              "wanted": "2.8.5"
            },
            "express": {
              "dependent": "mcp-server-chart",
              "latest": "5.1.0",
              "wanted": "5.1.0"
            },
            "zod": {
              "dependent": "mcp-server-chart",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            },
            "zod-to-json-schema": {
              "dependent": "mcp-server-chart",
              "latest": "3.24.6",
              "wanted": "3.24.6"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "solon",
      "owner": "opensolon",
      "fullName": "opensolon/solon",
      "url": "https://github.com/opensolon/solon",
      "stars": 2616,
      "description": "🔥 Java enterprise application development framework for full scenario: Restrained, Efficient, Open, Ecologicalll!!! 700% higher concurrency 50% memory savings Startup is 10 times faster. Packing 90% smaller; Compatible with java8 ~ java24. (Replaceable spring)",
      "language": "Java",
      "updatedAt": "2025-09-18T08:56:33Z",
      "scanDate": "2025-09-19T02:20:57.52624+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "XcodeBuildMCP",
      "owner": "cameroncooke",
      "fullName": "cameroncooke/XcodeBuildMCP",
      "url": "https://github.com/cameroncooke/XcodeBuildMCP",
      "stars": 2564,
      "description": "A Model Context Protocol (MCP) server that provides Xcode-related tools for integration with AI assistants and other MCP clients.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T11:48:41Z",
      "scanDate": "2025-09-19T02:21:00.532662+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 1,
          "moderate": 0,
          "total": 1
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 2,
          "medium": 0,
          "total": 2,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 5,
          "packages": {
            "@camsoft/mcp-sdk": {
              "dependent": "XcodeBuildMCP",
              "latest": "1.17.1",
              "wanted": "1.17.1"
            },
            "@sentry/cli": {
              "dependent": "XcodeBuildMCP",
              "latest": "2.54.0",
              "wanted": "2.54.0"
            },
            "@sentry/node": {
              "dependent": "XcodeBuildMCP",
              "latest": "10.12.0",
              "wanted": "10.12.0"
            },
            "uuid": {
              "dependent": "XcodeBuildMCP",
              "latest": "13.0.0",
              "wanted": "11.1.0"
            },
            "zod": {
              "dependent": "XcodeBuildMCP",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "py-xiaozhi",
      "owner": "huangjunsen0406",
      "fullName": "huangjunsen0406/py-xiaozhi",
      "url": "https://github.com/huangjunsen0406/py-xiaozhi",
      "stars": 2502,
      "description": "python版本的小智ai，主要帮助那些没有硬件却想体验小智功能的人,如果可以请点个小星星！",
      "language": "Python",
      "updatedAt": "2025-09-18T12:31:00Z",
      "scanDate": "2025-09-19T02:21:10.662491+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 2,
          "medium": 0,
          "total": 4,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-53643",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": " AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53643",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": " AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "nunu",
      "owner": "go-nunu",
      "fullName": "go-nunu/nunu",
      "url": "https://github.com/go-nunu/nunu",
      "stars": 2384,
      "description": "A CLI tool for building Go applications.",
      "language": "Go",
      "updatedAt": "2025-09-18T02:42:54Z",
      "scanDate": "2025-09-19T02:21:16.976575+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 65,
          "total": 65,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2022-24675",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack overflow from a large amount of PEM data in encoding/pem"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-28327",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Panic due to large inputs affecting P-256 curves in crypto/elliptic"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-29526",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect privilege reporting in syscall and golang.org/x/sys/unix"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30634",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Indefinite hang with large buffers on Windows in crypto/rand"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30629",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Session tickets lack random ticket_age_add in crypto/tls"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30580",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Empty Cmd.Path can trigger unintended binary in os/exec on Windows"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-29804",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Path traversal via Clean on Windows in path/filepath"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-1962",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion due to deeply nested types in go/parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-32148",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Exposure of client IP addresses in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-28131",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion from deeply nested XML documents in encoding/xml"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30632",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion on crafted paths in path/filepath"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30633",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion when unmarshaling certain documents in encoding/xml"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30631",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion when reading certain archives in compress/gzip"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-1705",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Improper sanitization of Transfer-Encoding headers in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30635",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion when decoding certain messages in encoding/gob"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-30630",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in Glob on certain paths in io/fs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-32189",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Panic when decoding Float and Rat types in math/big"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-27664",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Denial of service in net/http and golang.org/x/net/http2"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-2879",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Unbounded memory consumption when reading headers in archive/tar"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-2880",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect sanitization of forwarded query parameters in net/http/httputil"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41715",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Memory exhaustion when compiling regular expressions in regexp/syntax"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41716",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Unsanitized NUL in environment variables on Windows in syscall and os/exec"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41720",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Restricted file access on Windows in os and net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41717",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Excessive memory growth in net/http and golang.org/x/net/http2"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45287",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Before Go 1.20, the RSA based key exchange methods in crypto/tls may exhibit a timing side channel"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41722",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Path traversal on Windows in path/filepath"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41725",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Excessive resource consumption in mime/multipart"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41724",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Panic on large handshake records in crypto/tls"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-41723",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Denial of service via crafted HTTP/2 stream in net/http and golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-24532",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect calculation on P256 curves in crypto/internal/nistec"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-24537",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Infinite loop in parsing in go/scanner"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-24538",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Backticks not treated as string delimiters in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-24534",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Excessive memory allocation in net/http and net/textproto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-24536",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Excessive resource consumption in net/http, net/textproto and mime/multipart"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-24539",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Improper sanitization of CSS values in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-24540",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Improper handling of JavaScript whitespace in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-29400",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Improper handling of empty HTML attributes in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-29403",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Unsafe behavior in setuid/setgid binaries in runtime"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-29406",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Insufficient sanitization of Host header in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-29409",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Large RSA keys can cause high CPU usage in crypto/tls"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-39318",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Improper handling of HTML-like comments in script contexts in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-39319",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Improper handling of special tags within script contexts in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-39325",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "HTTP/2 rapid reset can cause excessive work in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45283",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Insecure parsing of Windows paths with a \\??\\ prefix in path/filepath"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45284",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect detection of reserved device names on Windows in path/filepath"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-39326",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Denial of service via chunk extensions in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24783",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Verify panics on certificates with an unknown public key algorithm in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45290",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Memory exhaustion in multipart form parsing in net/textproto and net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45289",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect forwarding of sensitive headers and cookies on HTTP redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24784",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Comments in display names are incorrectly handled in net/mail"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24785",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Errors returned from JSON marshaling may break template escaping in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45288",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "HTTP/2 CONTINUATION flood in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24790",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses in net/netip"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24789",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Mishandling of corrupt central directory record in archive/zip"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24791",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Denial of service due to improper 100-continue handling in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34155",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in all Parse functions in go/parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34156",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in Decoder.Decode in encoding/gob"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34158",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in Parse in go/build/constraint"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45341",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of IPv6 zone IDs can bypass URI name constraints in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45336",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers incorrectly sent after cross-domain redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22866",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "excel-mcp-server",
      "owner": "haris-musa",
      "fullName": "haris-musa/excel-mcp-server",
      "url": "https://github.com/haris-musa/excel-mcp-server",
      "stars": 2331,
      "description": "A Model Context Protocol server for Excel file manipulation",
      "language": "Python",
      "updatedAt": "2025-09-18T15:00:03Z",
      "scanDate": "2025-09-19T02:21:21.527099+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "claude-code-subagents-collection",
      "owner": "davepoon",
      "fullName": "davepoon/claude-code-subagents-collection",
      "url": "https://github.com/davepoon/claude-code-subagents-collection",
      "stars": 1767,
      "description": "Claude Code Subagents \u0026 Commands Collection + CLI Tool",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T15:52:27Z",
      "scanDate": "2025-09-19T02:21:22.868712+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 4,
          "moderate": 3,
          "total": 7
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 3,
          "medium": 0,
          "total": 5,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57822",
              "pkg": "next",
              "severity": "MODERATE",
              "title": "Next.js Improper Middleware Redirect Handling Leads to SSRF"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 5,
          "packages": {
            "ajv": {
              "dependent": "claude-code-subagents-collection",
              "latest": "8.17.1",
              "wanted": "8.17.1"
            },
            "ajv-formats": {
              "dependent": "claude-code-subagents-collection",
              "latest": "3.0.1",
              "wanted": "3.0.1"
            },
            "chalk": {
              "dependent": "claude-code-subagents-collection",
              "latest": "5.6.2",
              "wanted": "5.6.2"
            },
            "glob": {
              "dependent": "claude-code-subagents-collection",
              "latest": "11.0.3",
              "wanted": "11.0.3"
            },
            "gray-matter": {
              "dependent": "claude-code-subagents-collection",
              "latest": "4.0.3",
              "wanted": "4.0.3"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 77,
      "errors": []
    },
    {
      "name": "Unla",
      "owner": "AmoyLab",
      "fullName": "AmoyLab/Unla",
      "url": "https://github.com/AmoyLab/Unla",
      "stars": 1740,
      "description": "🧩 MCP Gateway - A lightweight gateway service that instantly transforms existing MCP Servers and APIs into MCP servers with zero code changes. Features Docker deployment and management UI, requiring no infrastructure modifications.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T14:10:00Z",
      "scanDate": "2025-09-19T02:21:44.273124+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 5,
          "total": 5,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22874",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of ExtKeyUsageAny disables policy validation in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": true,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 86,
      "errors": []
    },
    {
      "name": "mcp-shrimp-task-manager",
      "owner": "cjo4m06",
      "fullName": "cjo4m06/mcp-shrimp-task-manager",
      "url": "https://github.com/cjo4m06/mcp-shrimp-task-manager",
      "stars": 1725,
      "description": "Shrimp Task Manager is a task tool built for AI Agents, emphasizing chain-of-thought, reflection, and style consistency. It converts natural language into structured dev tasks with dependency tracking and iterative refinement, enabling agent-like developer behavior in reasoning AI systems.",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T12:56:36Z",
      "scanDate": "2025-09-19T02:21:54.823228+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 1,
          "moderate": 2,
          "total": 3
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 3,
          "medium": 0,
          "total": 4,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 7,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "mcp-shrimp-task-manager",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "dotenv": {
              "dependent": "mcp-shrimp-task-manager",
              "latest": "17.2.2",
              "wanted": "16.6.1"
            },
            "express": {
              "dependent": "mcp-shrimp-task-manager",
              "latest": "5.1.0",
              "wanted": "5.1.0"
            },
            "get-port": {
              "dependent": "mcp-shrimp-task-manager",
              "latest": "7.1.0",
              "wanted": "7.1.0"
            },
            "uuid": {
              "dependent": "mcp-shrimp-task-manager",
              "latest": "13.0.0",
              "wanted": "9.0.1"
            },
            "zod": {
              "dependent": "mcp-shrimp-task-manager",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            },
            "zod-to-json-schema": {
              "dependent": "mcp-shrimp-task-manager",
              "latest": "3.24.6",
              "wanted": "3.24.6"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 90,
      "errors": []
    },
    {
      "name": "mcp-proxy",
      "owner": "sparfenyuk",
      "fullName": "sparfenyuk/mcp-proxy",
      "url": "https://github.com/sparfenyuk/mcp-proxy",
      "stars": 1723,
      "description": "A bridge between Streamable HTTP and stdio MCP transports",
      "language": "Python",
      "updatedAt": "2025-09-18T15:30:22Z",
      "scanDate": "2025-09-19T02:22:01.16521+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "arxiv-mcp-server",
      "owner": "blazickjp",
      "fullName": "blazickjp/arxiv-mcp-server",
      "url": "https://github.com/blazickjp/arxiv-mcp-server",
      "stars": 1700,
      "description": "A Model Context Protocol server for searching and analyzing arXiv papers",
      "language": "Python",
      "updatedAt": "2025-09-18T15:38:51Z",
      "scanDate": "2025-09-19T02:22:02.379009+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "Dive",
      "owner": "OpenAgentPlatform",
      "fullName": "OpenAgentPlatform/Dive",
      "url": "https://github.com/OpenAgentPlatform/Dive",
      "stars": 1575,
      "description": "Dive is an open-source MCP Host Desktop Application that seamlessly integrates with any LLMs supporting function calling capabilities. ✨",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:28:45Z",
      "scanDate": "2025-09-19T02:22:03.656089+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 5,
          "moderate": 7,
          "total": 12
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 8,
          "medium": 0,
          "total": 18,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/helpers",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-xffm-g5w8-qvg7",
              "pkg": "@eslint/plugin-kit",
              "severity": "LOW",
              "title": "@eslint/plugin-kit is vulnerable to Regular Expression Denial of Service attacks through ConfigCommentParser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-55305",
              "pkg": "electron",
              "severity": "MODERATE",
              "title": "Electron has ASAR Integrity Bypass via resource modification"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53382",
              "pkg": "prismjs",
              "severity": "MODERATE",
              "title": "PrismJS DOM Clobbering vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53382",
              "pkg": "prismjs",
              "severity": "MODERATE",
              "title": "PrismJS DOM Clobbering vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-30208",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite bypasses server.fs.deny when using ?raw??"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-31125",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite has a `server.fs.deny` bypassed for `inline` and `raw` with `?import` query"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-31486",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite allows server.fs.deny to be bypassed with .svg or relative paths"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-32395",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite has an `server.fs.deny` bypass with an invalid `request-target`"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-46565",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite's server.fs.deny bypassed with /. for files under project root"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 14,
          "packages": {
            "@anthropic-ai/sdk": {
              "dependent": "Dive",
              "latest": "0.63.0",
              "wanted": "0.57.0"
            },
            "@aws-sdk/client-bedrock": {
              "dependent": "Dive",
              "latest": "3.891.0",
              "wanted": "3.891.0"
            },
            "@mistralai/mistralai": {
              "dependent": "Dive",
              "latest": "1.10.0",
              "wanted": "1.10.0"
            },
            "bufferutil": {
              "dependent": "Dive",
              "latest": "4.0.9",
              "wanted": "4.0.9"
            },
            "cross-spawn": {
              "dependent": "Dive",
              "latest": "7.0.6",
              "wanted": "7.0.6"
            },
            "electron-dl": {
              "dependent": "Dive",
              "latest": "4.0.0",
              "wanted": "4.0.0"
            },
            "electron-log": {
              "dependent": "Dive",
              "latest": "5.4.3",
              "wanted": "5.4.3"
            },
            "electron-store": {
              "dependent": "Dive",
              "latest": "10.1.0",
              "wanted": "10.1.0"
            },
            "electron-updater": {
              "dependent": "Dive",
              "latest": "6.6.2",
              "wanted": "6.6.2"
            },
            "fs-extra": {
              "dependent": "Dive",
              "latest": "11.3.2",
              "wanted": "11.3.2"
            },
            "ollama": {
              "dependent": "Dive",
              "latest": "0.5.18",
              "wanted": "0.5.18"
            },
            "openai": {
              "dependent": "Dive",
              "latest": "5.21.0",
              "wanted": "4.104.0"
            },
            "utf-8-validate": {
              "dependent": "Dive",
              "latest": "6.0.5",
              "wanted": "6.0.5"
            },
            "zod": {
              "dependent": "Dive",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 52,
      "errors": []
    },
    {
      "name": "UltraRAG",
      "owner": "OpenBMB",
      "fullName": "OpenBMB/UltraRAG",
      "url": "https://github.com/OpenBMB/UltraRAG",
      "stars": 1573,
      "description": "UltraRAG 2.0: Less Code, Lower Barrier, Faster Deployment! MCP-based low-code RAG framework, enabling researchers to build complex pipelines to creative innovation.",
      "language": "Python",
      "updatedAt": "2025-09-18T09:44:46Z",
      "scanDate": "2025-09-19T02:22:33.017184+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcphub.nvim",
      "owner": "ravitemer",
      "fullName": "ravitemer/mcphub.nvim",
      "url": "https://github.com/ravitemer/mcphub.nvim",
      "stars": 1523,
      "description": "An MCP client for Neovim that seamlessly integrates MCP servers into your editing workflow with an intuitive interface for managing, testing, and using MCP servers with your favorite chat plugins.",
      "language": "Lua",
      "updatedAt": "2025-09-18T11:53:54Z",
      "scanDate": "2025-09-19T02:22:34.328992+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "zenfeed",
      "owner": "glidea",
      "fullName": "glidea/zenfeed",
      "url": "https://github.com/glidea/zenfeed",
      "stars": 1510,
      "description": "Make RSS 📰 great again with AI 🧠✨!!",
      "language": "Go",
      "updatedAt": "2025-09-17T08:07:31Z",
      "scanDate": "2025-09-19T02:22:35.833108+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 7,
          "total": 7,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2024-45341",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of IPv6 zone IDs can bypass URI name constraints in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45336",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers incorrectly sent after cross-domain redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22866",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 73,
      "errors": []
    },
    {
      "name": "brightdata-mcp",
      "owner": "brightdata",
      "fullName": "brightdata/brightdata-mcp",
      "url": "https://github.com/brightdata/brightdata-mcp",
      "stars": 1325,
      "description": "A powerful Model Context Protocol (MCP) server that provides an all-in-one solution for public web access.",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T11:00:26Z",
      "scanDate": "2025-09-19T02:22:44.148089+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 1,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 1
        },
        "osv": {
          "critical": 0,
          "high": 1,
          "low": 0,
          "medium": 0,
          "total": 1,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            }
          ]
        },
        "outdated": {
          "count": 4,
          "packages": {
            "axios": {
              "dependent": "brightdata-mcp",
              "latest": "1.12.2",
              "wanted": "1.12.2"
            },
            "fastmcp": {
              "dependent": "brightdata-mcp",
              "latest": "3.17.0",
              "wanted": "3.17.0"
            },
            "playwright": {
              "dependent": "brightdata-mcp",
              "latest": "1.55.0",
              "wanted": "1.55.0"
            },
            "zod": {
              "dependent": "brightdata-mcp",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": false,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 84,
      "errors": []
    },
    {
      "name": "metamcp",
      "owner": "metatool-ai",
      "fullName": "metatool-ai/metamcp",
      "url": "https://github.com/metatool-ai/metamcp",
      "stars": 1324,
      "description": "MCP Aggregator, Orchestrator, Middleware, Gateway in one docker",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T08:17:50Z",
      "scanDate": "2025-09-19T02:22:50.347918+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 4,
          "medium": 0,
          "total": 7,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-xffm-g5w8-qvg7",
              "pkg": "@eslint/plugin-kit",
              "severity": "LOW",
              "title": "@eslint/plugin-kit is vulnerable to Regular Expression Denial of Service attacks through ConfigCommentParser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53535",
              "pkg": "better-auth",
              "severity": "LOW",
              "title": "Better Auth Open Redirect Vulnerability in originCheck Middleware Affects Multiple Routes"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-hq75-xg7r-rx6c",
              "pkg": "better-call",
              "severity": "MODERATE",
              "title": "Better Call routing bug can lead to Cache Deception"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53382",
              "pkg": "prismjs",
              "severity": "MODERATE",
              "title": "PrismJS DOM Clobbering vulnerability"
            }
          ]
        },
        "outdated": {
          "count": 0,
          "packages": {}
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 98,
      "errors": []
    },
    {
      "name": "dbhub",
      "owner": "bytebase",
      "fullName": "bytebase/dbhub",
      "url": "https://github.com/bytebase/dbhub",
      "stars": 1295,
      "description": "Universal database MCP server connecting to MySQL, PostgreSQL, SQL Server, MariaDB.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T14:40:15Z",
      "scanDate": "2025-09-19T02:23:02.708965+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 3,
          "medium": 0,
          "total": 4,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 12,
          "packages": {
            "@azure/identity": {
              "dependent": "dbhub",
              "latest": "4.12.0",
              "wanted": "4.12.0"
            },
            "@modelcontextprotocol/sdk": {
              "dependent": "dbhub",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "better-sqlite3": {
              "dependent": "dbhub",
              "latest": "12.2.0",
              "wanted": "11.10.0"
            },
            "dotenv": {
              "dependent": "dbhub",
              "latest": "17.2.2",
              "wanted": "16.6.1"
            },
            "express": {
              "dependent": "dbhub",
              "latest": "5.1.0",
              "wanted": "4.21.2"
            },
            "mariadb": {
              "dependent": "dbhub",
              "latest": "3.4.5",
              "wanted": "3.4.5"
            },
            "mssql": {
              "dependent": "dbhub",
              "latest": "11.0.1",
              "wanted": "11.0.1"
            },
            "mysql2": {
              "dependent": "dbhub",
              "latest": "3.15.0",
              "wanted": "3.15.0"
            },
            "pg": {
              "dependent": "dbhub",
              "latest": "8.16.3",
              "wanted": "8.16.3"
            },
            "ssh-config": {
              "dependent": "dbhub",
              "latest": "5.0.3",
              "wanted": "5.0.3"
            },
            "ssh2": {
              "dependent": "dbhub",
              "latest": "1.17.0",
              "wanted": "1.17.0"
            },
            "zod": {
              "dependent": "dbhub",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "rulego",
      "owner": "rulego",
      "fullName": "rulego/rulego",
      "url": "https://github.com/rulego/rulego",
      "stars": 1280,
      "description": "⛓️RuleGo is a lightweight, high-performance, embedded, next-generation component orchestration rule engine framework for Go.",
      "language": "Go",
      "updatedAt": "2025-09-18T02:45:10Z",
      "scanDate": "2025-09-19T02:23:12.061662+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 1,
          "high": 1,
          "low": 0,
          "medium": 24,
          "total": 28,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2024-45337",
              "pkg": "golang.org/x/crypto",
              "severity": "CRITICAL",
              "title": "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45337",
              "pkg": "golang.org/x/crypto",
              "severity": "MEDIUM",
              "title": "Misuse of connection.serverAuthenticate may cause authorization bypass in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22869",
              "pkg": "golang.org/x/crypto",
              "severity": "HIGH",
              "title": "golang.org/x/crypto Vulnerable to Denial of Service (DoS) via Slow or Incomplete Key Exchange"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22869",
              "pkg": "golang.org/x/crypto",
              "severity": "MEDIUM",
              "title": "Potential denial of service in golang.org/x/crypto"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45338",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "Non-linear parsing of case-insensitive content in golang.org/x/net/html"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22870",
              "pkg": "golang.org/x/net",
              "severity": "MODERATE",
              "title": "HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22870",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "HTTP Proxy bypass using IPv6 Zone IDs in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22872",
              "pkg": "golang.org/x/net",
              "severity": "MODERATE",
              "title": "golang.org/x/net vulnerable to Cross-site Scripting"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22872",
              "pkg": "golang.org/x/net",
              "severity": "MEDIUM",
              "title": "Incorrect Neutralization of Input During Web Page Generation in x/net in golang.org/x/net"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24783",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Verify panics on certificates with an unknown public key algorithm in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45290",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Memory exhaustion in multipart form parsing in net/textproto and net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45289",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect forwarding of sensitive headers and cookies on HTTP redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24784",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Comments in display names are incorrectly handled in net/mail"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24785",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Errors returned from JSON marshaling may break template escaping in html/template"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-45288",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "HTTP/2 CONTINUATION flood in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24790",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses in net/netip"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24789",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Mishandling of corrupt central directory record in archive/zip"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24791",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Denial of service due to improper 100-continue handling in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34155",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in all Parse functions in go/parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34156",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in Decoder.Decode in encoding/gob"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-34158",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Stack exhaustion in Parse in go/build/constraint"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45341",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of IPv6 zone IDs can bypass URI name constraints in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45336",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers incorrectly sent after cross-domain redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22866",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "lemonade",
      "owner": "lemonade-sdk",
      "fullName": "lemonade-sdk/lemonade",
      "url": "https://github.com/lemonade-sdk/lemonade",
      "stars": 1278,
      "description": "Lemonade helps users run local LLMs with the highest performance by configuring state-of-the-art inference engines for their NPUs and GPUs. Join our discord: https://discord.gg/5xXzkMu8Zk",
      "language": "Python",
      "updatedAt": "2025-09-18T15:36:33Z",
      "scanDate": "2025-09-19T02:23:19.294095+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcphub",
      "owner": "samanhappy",
      "fullName": "samanhappy/mcphub",
      "url": "https://github.com/samanhappy/mcphub",
      "stars": 1249,
      "description": "A unified hub for centralized management and dynamic organization of multiple MCP servers into streamable HTTP (SSE) endpoints, with support for flexible routing strategies",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T11:01:00Z",
      "scanDate": "2025-09-19T02:23:20.723946+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 1,
          "info": 0,
          "low": 1,
          "moderate": 0,
          "total": 2
        },
        "osv": {
          "critical": 0,
          "high": 1,
          "low": 2,
          "medium": 0,
          "total": 3,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 26,
          "packages": {
            "@apidevtools/swagger-parser": {
              "dependent": "mcphub",
              "latest": "12.0.0",
              "wanted": "12.0.0"
            },
            "@modelcontextprotocol/sdk": {
              "dependent": "mcphub",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "@types/adm-zip": {
              "dependent": "mcphub",
              "latest": "0.5.7",
              "wanted": "0.5.7"
            },
            "@types/bcrypt": {
              "dependent": "mcphub",
              "latest": "6.0.0",
              "wanted": "6.0.0"
            },
            "@types/multer": {
              "dependent": "mcphub",
              "latest": "2.0.0",
              "wanted": "1.4.13"
            },
            "@types/pg": {
              "dependent": "mcphub",
              "latest": "8.15.5",
              "wanted": "8.15.5"
            },
            "adm-zip": {
              "dependent": "mcphub",
              "latest": "0.5.16",
              "wanted": "0.5.16"
            },
            "axios": {
              "dependent": "mcphub",
              "latest": "1.12.2",
              "wanted": "1.12.2"
            },
            "bcrypt": {
              "dependent": "mcphub",
              "latest": "6.0.0",
              "wanted": "6.0.0"
            },
            "bcryptjs": {
              "dependent": "mcphub",
              "latest": "3.0.2",
              "wanted": "3.0.2"
            },
            "cors": {
              "dependent": "mcphub",
              "latest": "2.8.5",
              "wanted": "2.8.5"
            },
            "dotenv": {
              "dependent": "mcphub",
              "latest": "17.2.2",
              "wanted": "16.6.1"
            },
            "dotenv-expand": {
              "dependent": "mcphub",
              "latest": "12.0.3",
              "wanted": "12.0.3"
            },
            "express": {
              "dependent": "mcphub",
              "latest": "5.1.0",
              "wanted": "4.21.2"
            },
            "express-validator": {
              "dependent": "mcphub",
              "latest": "7.2.1",
              "wanted": "7.2.1"
            },
            "i18next-fs-backend": {
              "dependent": "mcphub",
              "latest": "2.6.0",
              "wanted": "2.6.0"
            },
            "jsonwebtoken": {
              "dependent": "mcphub",
              "latest": "9.0.2",
              "wanted": "9.0.2"
            },
            "multer": {
              "dependent": "mcphub",
              "latest": "2.0.2",
              "wanted": "2.0.2"
            },
            "openai": {
              "dependent": "mcphub",
              "latest": "5.21.0",
              "wanted": "4.104.0"
            },
            "openapi-types": {
              "dependent": "mcphub",
              "latest": "12.1.3",
              "wanted": "12.1.3"
            },
            "pg": {
              "dependent": "mcphub",
              "latest": "8.16.3",
              "wanted": "8.16.3"
            },
            "pgvector": {
              "dependent": "mcphub",
              "latest": "0.2.1",
              "wanted": "0.2.1"
            },
            "postgres": {
              "dependent": "mcphub",
              "latest": "3.4.7",
              "wanted": "3.4.7"
            },
            "reflect-metadata": {
              "dependent": "mcphub",
              "latest": "0.2.2",
              "wanted": "0.2.2"
            },
            "typeorm": {
              "dependent": "mcphub",
              "latest": "0.3.26",
              "wanted": "0.3.26"
            },
            "uuid": {
              "dependent": "mcphub",
              "latest": "13.0.0",
              "wanted": "11.1.0"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": true,
          "score": 6
        }
      },
      "securityScore": 89,
      "errors": []
    },
    {
      "name": "mcptools",
      "owner": "f",
      "fullName": "f/mcptools",
      "url": "https://github.com/f/mcptools",
      "stars": 1226,
      "description": "A command-line interface for interacting with MCP (Model Context Protocol) servers using both stdio and HTTP transport.",
      "language": "Go",
      "updatedAt": "2025-09-18T13:22:31Z",
      "scanDate": "2025-09-19T02:23:45.688217+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 7,
          "total": 9,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-fv92-fjc5-jj9h",
              "pkg": "github.com/go-viper/mapstructure/v2",
              "severity": "MODERATE",
              "title": "mapstructure May Leak Sensitive Information in Logs When Processing Malformed Data"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-fv92-fjc5-jj9h",
              "pkg": "github.com/go-viper/mapstructure/v2",
              "severity": "MEDIUM",
              "title": "May leak sensitive information in logs when processing malformed data in github.com/go-viper/mapstructure"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-2464-8j7c-4cjm",
              "pkg": "github.com/go-viper/mapstructure/v2",
              "severity": "MODERATE",
              "title": "go-viper's mapstructure May Leak Sensitive Information in Logs When Processing Malformed Data"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-2464-8j7c-4cjm",
              "pkg": "github.com/go-viper/mapstructure/v2",
              "severity": "MEDIUM",
              "title": "Go-viper's mapstructure May Leak Sensitive Information in Logs in github.com/go-viper/mapstructure"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22874",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of ExtKeyUsageAny disables policy validation in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 73,
      "errors": []
    },
    {
      "name": "awesome-hacking-lists",
      "owner": "taielab",
      "fullName": "taielab/awesome-hacking-lists",
      "url": "https://github.com/taielab/awesome-hacking-lists",
      "stars": 1193,
      "description": "A curated collection of top-tier penetration testing tools and productivity utilities across multiple domains. Join us to explore, contribute, and enhance your hacking toolkit!",
      "language": "",
      "updatedAt": "2025-09-18T11:51:28Z",
      "scanDate": "2025-09-19T02:23:51.131022+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 1
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "web-eval-agent",
      "owner": "Operative-Sh",
      "fullName": "Operative-Sh/web-eval-agent",
      "url": "https://github.com/Operative-Sh/web-eval-agent",
      "stars": 1185,
      "description": "An MCP server that autonomously evaluates web applications. ",
      "language": "Python",
      "updatedAt": "2025-09-18T11:54:05Z",
      "scanDate": "2025-09-19T02:23:54.57344+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 2,
          "high": 4,
          "low": 0,
          "medium": 1,
          "total": 11,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-47241",
              "pkg": "browser-use",
              "severity": "CRITICAL",
              "title": "Browser Use allows bypassing `allowed_domains` by putting a decoy domain in http auth username portion of a URL"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-43859",
              "pkg": "h11",
              "severity": "CRITICAL",
              "title": "h11 accepts some malformed Chunked-Encoding bodies"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53366",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53365",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4565",
              "pkg": "protobuf",
              "severity": "HIGH",
              "title": "protobuf-python has a potential Denial of Service issue"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47273",
              "pkg": "setuptools",
              "severity": "HIGH",
              "title": "setuptools has a path traversal vulnerability in PackageIndex.download that leads to Arbitrary File Write"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47273",
              "pkg": "setuptools",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54121",
              "pkg": "starlette",
              "severity": "MODERATE",
              "title": "Starlette has possible denial-of-service vector when parsing large files in multipart forms"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50182",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 does not control redirects in browsers and Node.js"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50181",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 31,
      "errors": []
    },
    {
      "name": "LitterBox",
      "owner": "BlackSnufkin",
      "fullName": "BlackSnufkin/LitterBox",
      "url": "https://github.com/BlackSnufkin/LitterBox",
      "stars": 1151,
      "description": "A secure sandbox environment for malware developers and red teamers to test payloads against detection mechanisms before deployment. Integrates with LLM agents via MCP for enhanced analysis capabilities.",
      "language": "YARA",
      "updatedAt": "2025-09-18T16:48:07Z",
      "scanDate": "2025-09-19T02:23:59.012463+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 1,
          "medium": 0,
          "total": 1,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-47278",
              "pkg": "flask",
              "severity": "LOW",
              "title": "Flask uses fallback key instead of current signing key"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcp-language-server",
      "owner": "isaacphi",
      "fullName": "isaacphi/mcp-language-server",
      "url": "https://github.com/isaacphi/mcp-language-server",
      "stars": 1107,
      "description": "mcp-language-server gives MCP enabled clients access semantic tools like get definition, references, rename, and diagnostics.",
      "language": "Go",
      "updatedAt": "2025-09-18T15:37:59Z",
      "scanDate": "2025-09-19T02:24:20.317318+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 5,
          "total": 5,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22874",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of ExtKeyUsageAny disables policy validation in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 84,
      "errors": []
    },
    {
      "name": "inspector",
      "owner": "MCPJam",
      "fullName": "MCPJam/inspector",
      "url": "https://github.com/MCPJam/inspector",
      "stars": 1029,
      "description": "MCP Testing Platform - Playground to test and debug MCP servers",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T16:39:03Z",
      "scanDate": "2025-09-19T02:24:24.827209+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 5,
          "moderate": 1,
          "total": 6
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 3,
          "medium": 0,
          "total": 4,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-59139",
              "pkg": "hono",
              "severity": "MODERATE",
              "title": "Hono has Body Limit Middleware Bypass"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-9910",
              "pkg": "jsondiffpatch",
              "severity": "LOW",
              "title": "jsondiffpatch is vulnerable to Cross-site Scripting (XSS) via HtmlFormatter::nodeBegin"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 57,
          "packages": {
            "@ai-sdk/anthropic": {
              "dependent": "inspector",
              "latest": "2.0.17",
              "wanted": "1.2.12"
            },
            "@ai-sdk/deepseek": {
              "dependent": "inspector",
              "latest": "1.0.18",
              "wanted": "1.0.18"
            },
            "@ai-sdk/google": {
              "dependent": "inspector",
              "latest": "2.0.14",
              "wanted": "2.0.14"
            },
            "@ai-sdk/openai": {
              "dependent": "inspector",
              "latest": "2.0.32",
              "wanted": "1.3.24"
            },
            "@ai-sdk/provider": {
              "dependent": "inspector",
              "latest": "2.0.0",
              "wanted": "2.0.0"
            },
            "@convex-dev/auth": {
              "dependent": "inspector",
              "latest": "0.0.89",
              "wanted": "0.0.88"
            },
            "@convex-dev/workos": {
              "dependent": "inspector",
              "latest": "0.0.1",
              "wanted": "0.0.1"
            },
            "@dnd-kit/core": {
              "dependent": "inspector",
              "latest": "6.3.1",
              "wanted": "6.3.1"
            },
            "@dnd-kit/modifiers": {
              "dependent": "inspector",
              "latest": "9.0.0",
              "wanted": "9.0.0"
            },
            "@dnd-kit/sortable": {
              "dependent": "inspector",
              "latest": "10.0.0",
              "wanted": "10.0.0"
            },
            "@dnd-kit/utilities": {
              "dependent": "inspector",
              "latest": "3.2.2",
              "wanted": "3.2.2"
            },
            "@hono/node-server": {
              "dependent": "inspector",
              "latest": "1.19.3",
              "wanted": "1.19.3"
            },
            "@hookform/resolvers": {
              "dependent": "inspector",
              "latest": "5.2.2",
              "wanted": "3.10.0"
            },
            "@mastra/core": {
              "dependent": "inspector",
              "latest": "0.17.1",
              "wanted": "0.16.0"
            },
            "@mastra/mcp": {
              "dependent": "inspector",
              "latest": "0.13.0",
              "wanted": "0.11.4"
            },
            "@modelcontextprotocol/sdk": {
              "dependent": "inspector",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "@tanstack/react-query": {
              "dependent": "inspector",
              "latest": "5.89.0",
              "wanted": "5.89.0"
            },
            "@tanstack/react-table": {
              "dependent": "inspector",
              "latest": "8.21.3",
              "wanted": "8.21.3"
            },
            "@uiw/react-json-view": {
              "dependent": "inspector",
              "latest": "2.0.0-alpha.38",
              "wanted": "2.0.0-alpha.38"
            },
            "@workos-inc/authkit-react": {
              "dependent": "inspector",
              "latest": "0.13.0",
              "wanted": "0.12.0"
            },
            "ai": {
              "dependent": "inspector",
              "latest": "5.0.45",
              "wanted": "5.0.45"
            },
            "ajv": {
              "dependent": "inspector",
              "latest": "8.17.1",
              "wanted": "8.17.1"
            },
            "class-variance-authority": {
              "dependent": "inspector",
              "latest": "0.7.1",
              "wanted": "0.7.1"
            },
            "classnames": {
              "dependent": "inspector",
              "latest": "2.5.1",
              "wanted": "2.5.1"
            },
            "clsx": {
              "dependent": "inspector",
              "latest": "2.1.1",
              "wanted": "2.1.1"
            },
            "cmdk": {
              "dependent": "inspector",
              "latest": "1.1.1",
              "wanted": "1.1.1"
            },
            "date-fns": {
              "dependent": "inspector",
              "latest": "4.1.0",
              "wanted": "3.6.0"
            },
            "electron-log": {
              "dependent": "inspector",
              "latest": "5.4.3",
              "wanted": "5.4.3"
            },
            "embla-carousel-react": {
              "dependent": "inspector",
              "latest": "8.6.0",
              "wanted": "8.6.0"
            },
            "fast-deep-equal": {
              "dependent": "inspector",
              "latest": "3.1.3",
              "wanted": "3.1.3"
            },
            "fix-path": {
              "dependent": "inspector",
              "latest": "5.0.0",
              "wanted": "4.0.0"
            },
            "framer-motion": {
              "dependent": "inspector",
              "latest": "12.23.15",
              "wanted": "12.23.15"
            },
            "hono": {
              "dependent": "inspector",
              "latest": "4.9.8",
              "wanted": "4.9.8"
            },
            "input-otp": {
              "dependent": "inspector",
              "latest": "1.4.2",
              "wanted": "1.4.2"
            },
            "lucide-react": {
              "dependent": "inspector",
              "latest": "0.544.0",
              "wanted": "0.525.0"
            },
            "next-themes": {
              "dependent": "inspector",
              "latest": "0.4.6",
              "wanted": "0.4.6"
            },
            "ollama-ai-provider": {
              "dependent": "inspector",
              "latest": "1.2.0",
              "wanted": "1.2.0"
            },
            "postcss": {
              "dependent": "inspector",
              "latest": "8.5.6",
              "wanted": "8.5.6"
            },
            "posthog-js": {
              "dependent": "inspector",
              "latest": "1.266.0",
              "wanted": "1.266.0"
            },
            "radix-ui": {
              "dependent": "inspector",
              "latest": "1.4.3",
              "wanted": "1.4.3"
            },
            "react": {
              "dependent": "inspector",
              "latest": "19.1.1",
              "wanted": "19.1.0"
            },
            "react-day-picker": {
              "dependent": "inspector",
              "latest": "9.10.0",
              "wanted": "9.10.0"
            },
            "react-dom": {
              "dependent": "inspector",
              "latest": "19.1.1",
              "wanted": "19.1.0"
            },
            "react-hook-form": {
              "dependent": "inspector",
              "latest": "7.62.0",
              "wanted": "7.62.0"
            },
            "react-markdown": {
              "dependent": "inspector",
              "latest": "10.1.0",
              "wanted": "10.1.0"
            },
            "react-resizable-panels": {
              "dependent": "inspector",
              "latest": "3.0.6",
              "wanted": "3.0.6"
            },
            "react18-json-view": {
              "dependent": "inspector",
              "latest": "0.2.9",
              "wanted": "0.2.9"
            },
            "recharts": {
              "dependent": "inspector",
              "latest": "3.2.1",
              "wanted": "2.15.4"
            },
            "remark-gfm": {
              "dependent": "inspector",
              "latest": "4.0.1",
              "wanted": "4.0.1"
            },
            "simple-icons": {
              "dependent": "inspector",
              "latest": "15.15.0",
              "wanted": "15.15.0"
            },
            "sonner": {
              "dependent": "inspector",
              "latest": "2.0.7",
              "wanted": "2.0.7"
            },
            "tailwind-merge": {
              "dependent": "inspector",
              "latest": "3.3.1",
              "wanted": "3.3.1"
            },
            "update-electron-app": {
              "dependent": "inspector",
              "latest": "3.1.1",
              "wanted": "3.1.1"
            },
            "vaul": {
              "dependent": "inspector",
              "latest": "1.1.2",
              "wanted": "1.1.2"
            },
            "zod": {
              "dependent": "inspector",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            },
            "zod-to-json-schema": {
              "dependent": "inspector",
              "latest": "3.24.6",
              "wanted": "3.24.6"
            },
            "zustand": {
              "dependent": "inspector",
              "latest": "5.0.8",
              "wanted": "5.0.8"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 87,
      "errors": []
    },
    {
      "name": "mcp-server-chatsum",
      "owner": "chatmcp",
      "fullName": "chatmcp/mcp-server-chatsum",
      "url": "https://github.com/chatmcp/mcp-server-chatsum",
      "stars": 1018,
      "description": "Query and Summarize your chat messages.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T11:48:31Z",
      "scanDate": "2025-09-19T02:24:43.777454+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 2,
          "low": 1,
          "medium": 0,
          "total": 3,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-12905",
              "pkg": "tar-fs",
              "severity": "HIGH",
              "title": "tar-fs Vulnerable to Link Following and Path Traversal via Extracting a Crafted tar File"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48387",
              "pkg": "tar-fs",
              "severity": "HIGH",
              "title": "tar-fs can extract outside the specified dir with a specific tarball"
            }
          ]
        },
        "outdated": {
          "count": 3,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "mcp-server-chatsum",
              "latest": "1.18.1",
              "wanted": "0.6.0"
            },
            "dotenv": {
              "dependent": "mcp-server-chatsum",
              "latest": "17.2.2",
              "wanted": "16.6.1"
            },
            "sqlite3": {
              "dependent": "mcp-server-chatsum",
              "latest": "5.1.7",
              "wanted": "5.1.7"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 1
        }
      },
      "securityScore": 80,
      "errors": []
    },
    {
      "name": "MiniMax-MCP",
      "owner": "MiniMax-AI",
      "fullName": "MiniMax-AI/MiniMax-MCP",
      "url": "https://github.com/MiniMax-AI/MiniMax-MCP",
      "stars": 947,
      "description": "Official MiniMax Model Context Protocol (MCP) server that enables interaction with powerful Text to Speech, image generation and video generation APIs.",
      "language": "Python",
      "updatedAt": "2025-09-17T21:09:47Z",
      "scanDate": "2025-09-19T02:24:49.361357+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "openops",
      "owner": "openops-cloud",
      "fullName": "openops-cloud/openops",
      "url": "https://github.com/openops-cloud/openops",
      "stars": 939,
      "description": "The batteries-included, No-Code FinOps automation platform, with the AI you trust.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T15:27:13Z",
      "scanDate": "2025-09-19T02:24:50.719648+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 2,
          "high": 2,
          "info": 0,
          "low": 9,
          "moderate": 17,
          "total": 30
        },
        "osv": {
          "critical": 2,
          "high": 2,
          "low": 9,
          "medium": 0,
          "total": 20,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/runtime",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-27789",
              "pkg": "@babel/runtime",
              "severity": "MODERATE",
              "title": "Babel has inefficient RegExp complexity in generated code with .replace when transpiling named capturing groups"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47764",
              "pkg": "cookie",
              "severity": "LOW",
              "title": "cookie accepts cookie name, path, and domain with out of bounds characters"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-21538",
              "pkg": "cross-spawn",
              "severity": "HIGH",
              "title": "Regular Expression Denial of Service (ReDoS) in cross-spawn"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-7783",
              "pkg": "form-data",
              "severity": "CRITICAL",
              "title": "form-data uses unsafe random function in form-data for choosing boundary"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-32379",
              "pkg": "koa",
              "severity": "MODERATE",
              "title": "Koajs vulnerable to Cross-Site Scripting (XSS) at ctx.redirect() function"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-8129",
              "pkg": "koa",
              "severity": "LOW",
              "title": "Koa Open Redirect via Referrer Header (User-Controlled)"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-7339",
              "pkg": "on-headers",
              "severity": "LOW",
              "title": "on-headers is vulnerable to http response header manipulation"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-53382",
              "pkg": "prismjs",
              "severity": "MODERATE",
              "title": "PrismJS DOM Clobbering vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-9288",
              "pkg": "sha.js",
              "severity": "CRITICAL",
              "title": "sha.js is missing type checks leading to hash rewind and passing on crafted data"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54798",
              "pkg": "tmp",
              "severity": "LOW",
              "title": "tmp allows arbitrary temporary file / directory write via symbolic link `dir` parameter"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 280,
          "packages": {
            "@ai-sdk/anthropic": {
              "dependent": "openops",
              "latest": "2.0.17",
              "wanted": "2.0.3"
            },
            "@ai-sdk/azure": {
              "dependent": "openops",
              "latest": "2.0.32",
              "wanted": "2.0.12"
            },
            "@ai-sdk/cerebras": {
              "dependent": "openops",
              "latest": "1.0.18",
              "wanted": "1.0.7"
            },
            "@ai-sdk/cohere": {
              "dependent": "openops",
              "latest": "2.0.10",
              "wanted": "2.0.3"
            },
            "@ai-sdk/deepinfra": {
              "dependent": "openops",
              "latest": "1.0.18",
              "wanted": "1.0.7"
            },
            "@ai-sdk/deepseek": {
              "dependent": "openops",
              "latest": "1.0.18",
              "wanted": "1.0.7"
            },
            "@ai-sdk/google": {
              "dependent": "openops",
              "latest": "2.0.14",
              "wanted": "2.0.6"
            },
            "@ai-sdk/google-vertex": {
              "dependent": "openops",
              "latest": "3.0.27",
              "wanted": "3.0.27"
            },
            "@ai-sdk/groq": {
              "dependent": "openops",
              "latest": "2.0.19",
              "wanted": "2.0.7"
            },
            "@ai-sdk/mistral": {
              "dependent": "openops",
              "latest": "2.0.14",
              "wanted": "2.0.4"
            },
            "@ai-sdk/openai": {
              "dependent": "openops",
              "latest": "2.0.32",
              "wanted": "2.0.12"
            },
            "@ai-sdk/perplexity": {
              "dependent": "openops",
              "latest": "2.0.9",
              "wanted": "2.0.3"
            },
            "@ai-sdk/react": {
              "dependent": "openops",
              "latest": "2.0.45",
              "wanted": "2.0.22"
            },
            "@ai-sdk/togetherai": {
              "dependent": "openops",
              "latest": "1.0.18",
              "wanted": "1.0.7"
            },
            "@ai-sdk/xai": {
              "dependent": "openops",
              "latest": "2.0.20",
              "wanted": "2.0.7"
            },
            "@assistant-ui/react": {
              "dependent": "openops",
              "latest": "0.11.10",
              "wanted": "0.10.43"
            },
            "@assistant-ui/react-ai-sdk": {
              "dependent": "openops",
              "latest": "1.1.0",
              "wanted": "1.0.4"
            },
            "@assistant-ui/react-markdown": {
              "dependent": "openops",
              "latest": "0.11.0",
              "wanted": "0.10.9"
            },
            "@aws-sdk/client-athena": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-cloudformation": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-compute-optimizer": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-ec2": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-organizations": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-pricing": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-rds": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-resource-groups-tagging-api": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-s3": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/client-sts": {
              "dependent": "openops",
              "latest": "3.891.0",
              "wanted": "3.635.0"
            },
            "@aws-sdk/util-arn-parser": {
              "dependent": "openops",
              "latest": "3.873.0",
              "wanted": "3.693.0"
            },
            "@babel/core": {
              "dependent": "openops",
              "latest": "7.28.4",
              "wanted": "7.28.4"
            },
            "@babel/preset-react": {
              "dependent": "openops",
              "latest": "7.27.1",
              "wanted": "7.27.1"
            },
            "@babel/runtime": {
              "dependent": "openops",
              "latest": "7.28.4",
              "wanted": "7.22.11"
            },
            "@bull-board/api": {
              "dependent": "openops",
              "latest": "6.12.7",
              "wanted": "5.9.1"
            },
            "@bull-board/fastify": {
              "dependent": "openops",
              "latest": "6.12.7",
              "wanted": "5.9.1"
            },
            "@cdktf/hcl2json": {
              "dependent": "openops",
              "latest": "0.21.0",
              "wanted": "0.21.0"
            },
            "@codemirror/lang-javascript": {
              "dependent": "openops",
              "latest": "6.2.4",
              "wanted": "6.2.2"
            },
            "@codemirror/lang-json": {
              "dependent": "openops",
              "latest": "6.0.2",
              "wanted": "6.0.1"
            },
            "@codemirror/legacy-modes": {
              "dependent": "openops",
              "latest": "6.5.1",
              "wanted": "6.5.1"
            },
            "@datastructures-js/queue": {
              "dependent": "openops",
              "latest": "4.3.0",
              "wanted": "4.2.3"
            },
            "@dnd-kit/core": {
              "dependent": "openops",
              "latest": "6.3.1",
              "wanted": "6.1.0"
            },
            "@dnd-kit/modifiers": {
              "dependent": "openops",
              "latest": "9.0.0",
              "wanted": "7.0.0"
            },
            "@dnd-kit/sortable": {
              "dependent": "openops",
              "latest": "10.0.0",
              "wanted": "8.0.0"
            },
            "@esbuild/darwin-arm64": {
              "dependent": "openops",
              "latest": "0.25.10",
              "wanted": "0.25.0"
            },
            "@fastify/basic-auth": {
              "dependent": "openops",
              "latest": "6.2.0",
              "wanted": "6.2.0"
            },
            "@fastify/cookie": {
              "dependent": "openops",
              "latest": "11.0.2",
              "wanted": "11.0.2"
            },
            "@fastify/cors": {
              "dependent": "openops",
              "latest": "11.1.0",
              "wanted": "11.0.1"
            },
            "@fastify/formbody": {
              "dependent": "openops",
              "latest": "8.0.2",
              "wanted": "8.0.2"
            },
            "@fastify/multipart": {
              "dependent": "openops",
              "latest": "9.2.1",
              "wanted": "9.0.3"
            },
            "@fastify/rate-limit": {
              "dependent": "openops",
              "latest": "10.3.0",
              "wanted": "10.3.0"
            },
            "@fastify/request-context": {
              "dependent": "openops",
              "latest": "6.2.1",
              "wanted": "6.2.0"
            },
            "@fastify/swagger": {
              "dependent": "openops",
              "latest": "9.5.1",
              "wanted": "9.5.1"
            },
            "@fastify/swagger-ui": {
              "dependent": "openops",
              "latest": "5.2.3",
              "wanted": "5.2.3"
            },
            "@fastify/type-provider-typebox": {
              "dependent": "openops",
              "latest": "5.2.0",
              "wanted": "5.1.0"
            },
            "@frontegg/client": {
              "dependent": "openops",
              "latest": "5.3.2",
              "wanted": "5.3.2"
            },
            "@frontegg/js": {
              "dependent": "openops",
              "latest": "7.89.0",
              "wanted": "7.79.0"
            },
            "@hookform/resolvers": {
              "dependent": "openops",
              "latest": "5.2.2",
              "wanted": "3.9.0"
            },
            "@linear/sdk": {
              "dependent": "openops",
              "latest": "60.0.0",
              "wanted": "7.0.1"
            },
            "@microsoft/microsoft-graph-client": {
              "dependent": "openops",
              "latest": "3.0.7",
              "wanted": "3.0.7"
            },
            "@microsoft/microsoft-graph-types": {
              "dependent": "openops",
              "latest": "2.40.0",
              "wanted": "2.40.0"
            },
            "@monaco-editor/react": {
              "dependent": "openops",
              "latest": "4.7.0",
              "wanted": "4.7.0"
            },
            "@nx/devkit": {
              "dependent": "openops",
              "latest": "21.5.2",
              "wanted": "19.8.8"
            },
            "@nx/nx-darwin-arm64": {
              "dependent": "openops",
              "latest": "21.5.2",
              "wanted": "19.8.8"
            },
            "@nx/nx-darwin-x64": {
              "dependent": "openops",
              "latest": "21.5.2",
              "wanted": "19.8.8"
            },
            "@nx/nx-linux-arm-gnueabihf": {
              "dependent": "openops",
              "latest": "21.5.2",
              "wanted": "19.8.8"
            },
            "@nx/nx-linux-x64-gnu": {
              "dependent": "openops",
              "latest": "21.5.2",
              "wanted": "19.8.8"
            },
            "@nx/nx-win32-x64-msvc": {
              "dependent": "openops",
              "latest": "21.5.2",
              "wanted": "19.8.8"
            },
            "@opentelemetry/api-logs": {
              "dependent": "openops",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/auto-instrumentations-node": {
              "dependent": "openops",
              "latest": "0.64.1",
              "wanted": "0.62.0"
            },
            "@opentelemetry/instrumentation": {
              "dependent": "openops",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/sdk-node": {
              "dependent": "openops",
              "latest": "0.205.0",
              "wanted": "0.203.0"
            },
            "@opentelemetry/sdk-trace-base": {
              "dependent": "openops",
              "latest": "2.1.0",
              "wanted": "2.0.1"
            },
            "@radix-ui/react-avatar": {
              "dependent": "openops",
              "latest": "1.1.10",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-checkbox": {
              "dependent": "openops",
              "latest": "1.3.3",
              "wanted": "1.1.1"
            },
            "@radix-ui/react-collapsible": {
              "dependent": "openops",
              "latest": "1.1.12",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-context-menu": {
              "dependent": "openops",
              "latest": "2.2.16",
              "wanted": "2.2.6"
            },
            "@radix-ui/react-dialog": {
              "dependent": "openops",
              "latest": "1.1.15",
              "wanted": "1.1.1"
            },
            "@radix-ui/react-dropdown-menu": {
              "dependent": "openops",
              "latest": "2.1.16",
              "wanted": "2.1.1"
            },
            "@radix-ui/react-icons": {
              "dependent": "openops",
              "latest": "1.3.2",
              "wanted": "1.3.0"
            },
            "@radix-ui/react-label": {
              "dependent": "openops",
              "latest": "2.1.7",
              "wanted": "2.1.0"
            },
            "@radix-ui/react-popover": {
              "dependent": "openops",
              "latest": "1.1.15",
              "wanted": "1.1.1"
            },
            "@radix-ui/react-progress": {
              "dependent": "openops",
              "latest": "1.1.7",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-radio-group": {
              "dependent": "openops",
              "latest": "1.3.8",
              "wanted": "1.2.0"
            },
            "@radix-ui/react-scroll-area": {
              "dependent": "openops",
              "latest": "1.2.10",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-select": {
              "dependent": "openops",
              "latest": "2.2.6",
              "wanted": "2.1.1"
            },
            "@radix-ui/react-separator": {
              "dependent": "openops",
              "latest": "1.1.7",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-slot": {
              "dependent": "openops",
              "latest": "1.2.3",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-switch": {
              "dependent": "openops",
              "latest": "1.2.6",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-tabs": {
              "dependent": "openops",
              "latest": "1.1.13",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-toast": {
              "dependent": "openops",
              "latest": "1.2.15",
              "wanted": "1.2.1"
            },
            "@radix-ui/react-toggle": {
              "dependent": "openops",
              "latest": "1.1.10",
              "wanted": "1.1.0"
            },
            "@radix-ui/react-toggle-group": {
              "dependent": "openops",
              "latest": "1.1.11",
              "wanted": "1.1.2"
            },
            "@radix-ui/react-tooltip": {
              "dependent": "openops",
              "latest": "1.2.8",
              "wanted": "1.1.3"
            },
            "@rollup/plugin-commonjs": {
              "dependent": "openops",
              "latest": "28.0.6",
              "wanted": "28.0.1"
            },
            "@rollup/plugin-json": {
              "dependent": "openops",
              "latest": "6.1.0",
              "wanted": "6.1.0"
            },
            "@rollup/plugin-node-resolve": {
              "dependent": "openops",
              "latest": "16.0.1",
              "wanted": "15.3.0"
            },
            "@rollup/rollup-darwin-arm64": {
              "dependent": "openops",
              "latest": "4.50.2",
              "wanted": "4.20.0"
            },
            "@rollup/rollup-linux-arm64-gnu": {
              "dependent": "openops",
              "latest": "4.50.2",
              "wanted": "4.20.0"
            },
            "@segment/analytics-next": {
              "dependent": "openops",
              "latest": "1.81.1",
              "wanted": "1.72.0"
            },
            "@segment/analytics-node": {
              "dependent": "openops",
              "latest": "2.3.0",
              "wanted": "2.1.0"
            },
            "@sinclair/typebox": {
              "dependent": "openops",
              "latest": "0.34.41",
              "wanted": "0.32.35"
            },
            "@socket.io/redis-adapter": {
              "dependent": "openops",
              "latest": "8.3.0",
              "wanted": "8.2.1"
            },
            "@superset-ui/embedded-sdk": {
              "dependent": "openops",
              "latest": "0.2.0",
              "wanted": "0.1.2"
            },
            "@swc/core-darwin-arm64": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-darwin-x64": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-linux-arm-gnueabihf": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-linux-arm64-gnu": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-linux-arm64-musl": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-linux-x64-gnu": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-linux-x64-musl": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-win32-arm64-msvc": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-win32-ia32-msvc": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@swc/core-win32-x64-msvc": {
              "dependent": "openops",
              "latest": "1.13.5",
              "wanted": "1.7.42"
            },
            "@tanstack/react-query": {
              "dependent": "openops",
              "latest": "5.89.0",
              "wanted": "5.51.1"
            },
            "@tanstack/react-table": {
              "dependent": "openops",
              "latest": "8.21.3",
              "wanted": "8.19.2"
            },
            "@tiptap/extension-mention": {
              "dependent": "openops",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/extension-placeholder": {
              "dependent": "openops",
              "latest": "3.4.4",
              "wanted": "2.5.5"
            },
            "@tiptap/pm": {
              "dependent": "openops",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/react": {
              "dependent": "openops",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/starter-kit": {
              "dependent": "openops",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@tiptap/suggestion": {
              "dependent": "openops",
              "latest": "3.4.4",
              "wanted": "2.5.4"
            },
            "@types/js-yaml": {
              "dependent": "openops",
              "latest": "4.0.9",
              "wanted": "4.0.9"
            },
            "@types/jsonwebtoken": {
              "dependent": "openops",
              "latest": "9.0.10",
              "wanted": "9.0.1"
            },
            "@types/node": {
              "dependent": "openops",
              "latest": "24.5.2",
              "wanted": "20.17.1"
            },
            "@types/showdown": {
              "dependent": "openops",
              "latest": "2.0.6",
              "wanted": "2.0.6"
            },
            "@types/uuid": {
              "dependent": "openops",
              "latest": "10.0.0",
              "wanted": "10.0.0"
            },
            "@types/validator": {
              "dependent": "openops",
              "latest": "13.15.3",
              "wanted": "13.12.2"
            },
            "@uiw/codemirror-theme-github": {
              "dependent": "openops",
              "latest": "4.25.2",
              "wanted": "4.23.0"
            },
            "@uiw/react-codemirror": {
              "dependent": "openops",
              "latest": "4.25.2",
              "wanted": "4.23.0"
            },
            "@vercel/otel": {
              "dependent": "openops",
              "latest": "1.13.0",
              "wanted": "1.13.0"
            },
            "@xyflow/react": {
              "dependent": "openops",
              "latest": "12.8.5",
              "wanted": "12.4.4"
            },
            "ai": {
              "dependent": "openops",
              "latest": "5.0.45",
              "wanted": "5.0.11"
            },
            "ajv": {
              "dependent": "openops",
              "latest": "8.17.1",
              "wanted": "8.12.0"
            },
            "async-mutex": {
              "dependent": "openops",
              "latest": "0.5.0",
              "wanted": "0.4.0"
            },
            "aws-lambda": {
              "dependent": "openops",
              "latest": "1.0.7",
              "wanted": "1.0.7"
            },
            "axios": {
              "dependent": "openops",
              "latest": "1.12.2",
              "wanted": "1.8.2"
            },
            "axios-retry": {
              "dependent": "openops",
              "latest": "4.5.0",
              "wanted": "4.4.1"
            },
            "bcrypt": {
              "dependent": "openops",
              "latest": "6.0.0",
              "wanted": "5.1.1"
            },
            "bullmq": {
              "dependent": "openops",
              "latest": "5.58.5",
              "wanted": "5.8.3"
            },
            "chokidar": {
              "dependent": "openops",
              "latest": "4.0.3",
              "wanted": "3.6.0"
            },
            "class-variance-authority": {
              "dependent": "openops",
              "latest": "0.7.1",
              "wanted": "0.7.0"
            },
            "classnames": {
              "dependent": "openops",
              "latest": "2.5.1",
              "wanted": "2.5.1"
            },
            "clear-module": {
              "dependent": "openops",
              "latest": "4.1.2",
              "wanted": "4.1.2"
            },
            "cli-table3": {
              "dependent": "openops",
              "latest": "0.6.5",
              "wanted": "0.6.3"
            },
            "clipboard": {
              "dependent": "openops",
              "latest": "2.0.11",
              "wanted": "2.0.11"
            },
            "clsx": {
              "dependent": "openops",
              "latest": "2.1.1",
              "wanted": "2.1.1"
            },
            "cmdk": {
              "dependent": "openops",
              "latest": "1.1.1",
              "wanted": "0.2.1"
            },
            "codemirror": {
              "dependent": "openops",
              "latest": "6.0.2",
              "wanted": "5.65.14"
            },
            "color": {
              "dependent": "openops",
              "latest": "5.0.2",
              "wanted": "4.2.3"
            },
            "commander": {
              "dependent": "openops",
              "latest": "14.0.1",
              "wanted": "11.1.0"
            },
            "compare-versions": {
              "dependent": "openops",
              "latest": "6.1.1",
              "wanted": "6.1.0"
            },
            "concat": {
              "dependent": "openops",
              "latest": "1.0.3",
              "wanted": "1.0.3"
            },
            "contrast-color": {
              "dependent": "openops",
              "latest": "1.0.1",
              "wanted": "1.0.1"
            },
            "cron-parser": {
              "dependent": "openops",
              "latest": "5.4.0",
              "wanted": "4.9.0"
            },
            "cron-validator": {
              "dependent": "openops",
              "latest": "1.4.0",
              "wanted": "1.3.1"
            },
            "cronstrue": {
              "dependent": "openops",
              "latest": "3.3.0",
              "wanted": "2.31.0"
            },
            "cross-env": {
              "dependent": "openops",
              "latest": "10.0.0",
              "wanted": "7.0.3"
            },
            "date-fns": {
              "dependent": "openops",
              "latest": "4.1.0",
              "wanted": "3.6.0"
            },
            "dayjs": {
              "dependent": "openops",
              "latest": "1.11.18",
              "wanted": "1.11.10"
            },
            "decimal.js": {
              "dependent": "openops",
              "latest": "10.6.0",
              "wanted": "10.4.3"
            },
            "decompress": {
              "dependent": "openops",
              "latest": "4.2.1",
              "wanted": "4.2.1"
            },
            "deepmerge-ts": {
              "dependent": "openops",
              "latest": "7.1.5",
              "wanted": "7.1.0"
            },
            "dotenv": {
              "dependent": "openops",
              "latest": "17.2.2",
              "wanted": "16.4.5"
            },
            "embla-carousel-react": {
              "dependent": "openops",
              "latest": "8.6.0",
              "wanted": "8.1.8"
            },
            "fast-deep-equal": {
              "dependent": "openops",
              "latest": "3.1.3",
              "wanted": "3.1.3"
            },
            "fastify": {
              "dependent": "openops",
              "latest": "5.6.0",
              "wanted": "5.4.0"
            },
            "fastify-favicon": {
              "dependent": "openops",
              "latest": "5.0.0",
              "wanted": "5.0.0"
            },
            "fastify-plugin": {
              "dependent": "openops",
              "latest": "5.0.1",
              "wanted": "5.0.1"
            },
            "fastify-raw-body": {
              "dependent": "openops",
              "latest": "5.0.0",
              "wanted": "5.0.0"
            },
            "fastify-socket.io": {
              "dependent": "openops",
              "latest": "5.1.0",
              "wanted": "5.1.0"
            },
            "firebase-scrypt": {
              "dependent": "openops",
              "latest": "2.2.0",
              "wanted": "2.2.0"
            },
            "form-data": {
              "dependent": "openops",
              "latest": "4.0.4",
              "wanted": "4.0.0"
            },
            "fs-extra": {
              "dependent": "openops",
              "latest": "11.3.2",
              "wanted": "11.2.0"
            },
            "fuse.js": {
              "dependent": "openops",
              "latest": "7.1.0",
              "wanted": "7.0.0"
            },
            "http-status-codes": {
              "dependent": "openops",
              "latest": "2.3.0",
              "wanted": "2.2.0"
            },
            "https-proxy-agent": {
              "dependent": "openops",
              "latest": "7.0.6",
              "wanted": "7.0.4"
            },
            "i18next": {
              "dependent": "openops",
              "latest": "25.5.2",
              "wanted": "23.13.0"
            },
            "i18next-browser-languagedetector": {
              "dependent": "openops",
              "latest": "8.2.0",
              "wanted": "8.0.0"
            },
            "i18next-http-backend": {
              "dependent": "openops",
              "latest": "3.0.2",
              "wanted": "2.5.2"
            },
            "i18next-icu": {
              "dependent": "openops",
              "latest": "2.4.0",
              "wanted": "2.3.0"
            },
            "import-fresh": {
              "dependent": "openops",
              "latest": "3.3.1",
              "wanted": "3.3.0"
            },
            "intl-messageformat": {
              "dependent": "openops",
              "latest": "10.7.16",
              "wanted": "10.5.14"
            },
            "ioredis": {
              "dependent": "openops",
              "latest": "5.7.0",
              "wanted": "5.4.1"
            },
            "ip-range-check": {
              "dependent": "openops",
              "latest": "0.2.0",
              "wanted": "0.2.0"
            },
            "is-base64": {
              "dependent": "openops",
              "latest": "1.1.0",
              "wanted": "1.1.0"
            },
            "isolated-vm": {
              "dependent": "openops",
              "latest": "6.0.1",
              "wanted": "5.0.1"
            },
            "js-yaml": {
              "dependent": "openops",
              "latest": "4.1.0",
              "wanted": "4.1.0"
            },
            "jsdom": {
              "dependent": "openops",
              "latest": "27.0.0",
              "wanted": "23.0.1"
            },
            "jshint": {
              "dependent": "openops",
              "latest": "2.13.6",
              "wanted": "2.13.6"
            },
            "json-server": {
              "dependent": "openops",
              "latest": "1.0.0-beta.3",
              "wanted": "1.0.0-beta.0"
            },
            "json-to-pretty-yaml": {
              "dependent": "openops",
              "latest": "1.2.2",
              "wanted": "1.2.2"
            },
            "jsoneditor": {
              "dependent": "openops",
              "latest": "10.4.1",
              "wanted": "10.0.3"
            },
            "jsonlint-mod": {
              "dependent": "openops",
              "latest": "1.7.6",
              "wanted": "1.7.6"
            },
            "jsonrepair": {
              "dependent": "openops",
              "latest": "3.13.0",
              "wanted": "3.2.0"
            },
            "jsonwebtoken": {
              "dependent": "openops",
              "latest": "9.0.2",
              "wanted": "9.0.1"
            },
            "jszip": {
              "dependent": "openops",
              "latest": "3.10.1",
              "wanted": "3.10.1"
            },
            "jwt-decode": {
              "dependent": "openops",
              "latest": "4.0.0",
              "wanted": "4.0.0"
            },
            "langfuse-vercel": {
              "dependent": "openops",
              "latest": "3.38.5",
              "wanted": "3.38.4"
            },
            "localforage": {
              "dependent": "openops",
              "latest": "1.10.0",
              "wanted": "1.10.0"
            },
            "lodash-es": {
              "dependent": "openops",
              "latest": "4.17.21",
              "wanted": "4.17.21"
            },
            "lodash.debounce": {
              "dependent": "openops",
              "latest": "4.0.8",
              "wanted": "4.0.8"
            },
            "logzio-nodejs": {
              "dependent": "openops",
              "latest": "2.5.0",
              "wanted": "2.5.0"
            },
            "lottie-web": {
              "dependent": "openops",
              "latest": "5.13.0",
              "wanted": "5.12.2"
            },
            "lru-cache": {
              "dependent": "openops",
              "latest": "11.2.1",
              "wanted": "7.18.3"
            },
            "lucide-react": {
              "dependent": "openops",
              "latest": "0.544.0",
              "wanted": "0.407.0"
            },
            "markdown-to-text": {
              "dependent": "openops",
              "latest": "0.1.1",
              "wanted": "0.1.1"
            },
            "marked": {
              "dependent": "openops",
              "latest": "16.3.0",
              "wanted": "4.3.0"
            },
            "mime": {
              "dependent": "openops",
              "latest": "4.1.0",
              "wanted": "4.0.1"
            },
            "mime-types": {
              "dependent": "openops",
              "latest": "3.0.1",
              "wanted": "2.1.35"
            },
            "monaco-editor": {
              "dependent": "openops",
              "latest": "0.53.0",
              "wanted": "0.44.0"
            },
            "monday-sdk-js": {
              "dependent": "openops",
              "latest": "0.5.6",
              "wanted": "0.5.2"
            },
            "msgpackr": {
              "dependent": "openops",
              "latest": "1.11.5",
              "wanted": "1.11.5"
            },
            "nanoid": {
              "dependent": "openops",
              "latest": "5.1.5",
              "wanted": "3.3.8"
            },
            "node-cron": {
              "dependent": "openops",
              "latest": "4.2.1",
              "wanted": "3.0.3"
            },
            "nodemailer": {
              "dependent": "openops",
              "latest": "7.0.6",
              "wanted": "6.9.9"
            },
            "npm": {
              "dependent": "openops",
              "latest": "11.6.0",
              "wanted": "10.8.2"
            },
            "nx-cloud": {
              "dependent": "openops",
              "latest": "19.1.0",
              "wanted": "19.1.0"
            },
            "object-sizeof": {
              "dependent": "openops",
              "latest": "2.6.5",
              "wanted": "2.6.3"
            },
            "pdf-parse": {
              "dependent": "openops",
              "latest": "1.1.1",
              "wanted": "1.1.1"
            },
            "pg": {
              "dependent": "openops",
              "latest": "8.16.3",
              "wanted": "8.11.3"
            },
            "pickleparser": {
              "dependent": "openops",
              "latest": "0.2.1",
              "wanted": "0.1.0"
            },
            "pino": {
              "dependent": "openops",
              "latest": "9.10.0",
              "wanted": "8.21.0"
            },
            "posthog-js": {
              "dependent": "openops",
              "latest": "1.266.0",
              "wanted": "1.140.1"
            },
            "priority-queue-typescript": {
              "dependent": "openops",
              "latest": "2.0.3",
              "wanted": "1.0.1"
            },
            "prismjs": {
              "dependent": "openops",
              "latest": "1.30.0",
              "wanted": "1.30.0"
            },
            "product-fruits": {
              "dependent": "openops",
              "latest": "1.0.27",
              "wanted": "1.0.23"
            },
            "prometheus-remote-write": {
              "dependent": "openops",
              "latest": "0.5.1",
              "wanted": "0.4.1"
            },
            "qs": {
              "dependent": "openops",
              "latest": "6.14.0",
              "wanted": "6.11.2"
            },
            "react": {
              "dependent": "openops",
              "latest": "19.1.1",
              "wanted": "18.3.1"
            },
            "react-accessible-treeview": {
              "dependent": "openops",
              "latest": "2.11.2",
              "wanted": "2.10.0"
            },
            "react-colorful": {
              "dependent": "openops",
              "latest": "5.6.1",
              "wanted": "5.6.1"
            },
            "react-day-picker": {
              "dependent": "openops",
              "latest": "9.10.0",
              "wanted": "8.10.1"
            },
            "react-dom": {
              "dependent": "openops",
              "latest": "19.1.1",
              "wanted": "18.3.1"
            },
            "react-error-boundary": {
              "dependent": "openops",
              "latest": "6.0.0",
              "wanted": "4.1.2"
            },
            "react-helmet-async": {
              "dependent": "openops",
              "latest": "2.0.5",
              "wanted": "2.0.5"
            },
            "react-hook-form": {
              "dependent": "openops",
              "latest": "7.62.0",
              "wanted": "7.52.2"
            },
            "react-i18next": {
              "dependent": "openops",
              "latest": "15.7.3",
              "wanted": "15.0.1"
            },
            "react-markdown": {
              "dependent": "openops",
              "latest": "10.1.0",
              "wanted": "9.0.1"
            },
            "react-resizable-panels": {
              "dependent": "openops",
              "latest": "3.0.6",
              "wanted": "3.0.5"
            },
            "react-ripples": {
              "dependent": "openops",
              "latest": "2.2.1",
              "wanted": "2.2.1"
            },
            "react-router-dom": {
              "dependent": "openops",
              "latest": "7.9.1",
              "wanted": "7.5.2"
            },
            "react-syntax-highlighter": {
              "dependent": "openops",
              "latest": "15.6.6",
              "wanted": "15.5.0"
            },
            "react-textarea-autosize": {
              "dependent": "openops",
              "latest": "8.5.9",
              "wanted": "8.5.9"
            },
            "react-use": {
              "dependent": "openops",
              "latest": "17.6.0",
              "wanted": "17.5.1"
            },
            "recharts": {
              "dependent": "openops",
              "latest": "3.2.1",
              "wanted": "2.12.7"
            },
            "redlock": {
              "dependent": "openops",
              "latest": "5.0.0-beta.2",
              "wanted": "5.0.0-beta.2"
            },
            "remark-gfm": {
              "dependent": "openops",
              "latest": "4.0.1",
              "wanted": "4.0.1"
            },
            "rollup": {
              "dependent": "openops",
              "latest": "4.50.2",
              "wanted": "4.24.0"
            },
            "rss-parser": {
              "dependent": "openops",
              "latest": "3.13.0",
              "wanted": "3.13.0"
            },
            "rxjs": {
              "dependent": "openops",
              "latest": "7.8.2",
              "wanted": "7.8.1"
            },
            "semver": {
              "dependent": "openops",
              "latest": "7.7.2",
              "wanted": "7.6.0"
            },
            "shade-generator": {
              "dependent": "openops",
              "latest": "1.2.7",
              "wanted": "1.2.7"
            },
            "shell-quote": {
              "dependent": "openops",
              "latest": "1.8.3",
              "wanted": "1.8.1"
            },
            "showdown": {
              "dependent": "openops",
              "latest": "2.1.0",
              "wanted": "2.1.0"
            },
            "snowflake-sdk": {
              "dependent": "openops",
              "latest": "2.2.0",
              "wanted": "1.9.3"
            },
            "socket.io": {
              "dependent": "openops",
              "latest": "4.8.1",
              "wanted": "4.7.5"
            },
            "socket.io-client": {
              "dependent": "openops",
              "latest": "4.8.1",
              "wanted": "4.7.5"
            },
            "sqlite3": {
              "dependent": "openops",
              "latest": "5.1.7",
              "wanted": "5.1.7"
            },
            "ssh2-sftp-client": {
              "dependent": "openops",
              "latest": "12.0.1",
              "wanted": "9.1.0"
            },
            "string-strip-html": {
              "dependent": "openops",
              "latest": "13.4.13",
              "wanted": "8.5.0"
            },
            "subsink": {
              "dependent": "openops",
              "latest": "1.0.2",
              "wanted": "1.0.2"
            },
            "tailwind-merge": {
              "dependent": "openops",
              "latest": "3.3.1",
              "wanted": "2.4.0"
            },
            "tailwindcss-animate": {
              "dependent": "openops",
              "latest": "1.0.7",
              "wanted": "1.0.7"
            },
            "tinycolor2": {
              "dependent": "openops",
              "latest": "1.6.0",
              "wanted": "1.6.0"
            },
            "tsconfig-paths": {
              "dependent": "openops",
              "latest": "4.2.0",
              "wanted": "4.2.0"
            },
            "tslib": {
              "dependent": "openops",
              "latest": "2.8.1",
              "wanted": "2.6.2"
            },
            "turndown": {
              "dependent": "openops",
              "latest": "7.2.1",
              "wanted": "7.2.0"
            },
            "typeorm": {
              "dependent": "openops",
              "latest": "0.3.26",
              "wanted": "0.3.18"
            },
            "url": {
              "dependent": "openops",
              "latest": "0.11.4",
              "wanted": "0.11.3"
            },
            "use-debounce": {
              "dependent": "openops",
              "latest": "10.0.6",
              "wanted": "10.0.1"
            },
            "use-ripple-hook": {
              "dependent": "openops",
              "latest": "1.0.24",
              "wanted": "1.0.24"
            },
            "usehooks-ts": {
              "dependent": "openops",
              "latest": "3.1.1",
              "wanted": "3.1.0"
            },
            "uuid": {
              "dependent": "openops",
              "latest": "13.0.0",
              "wanted": "10.0.0"
            },
            "validator": {
              "dependent": "openops",
              "latest": "13.15.15",
              "wanted": "13.12.0"
            },
            "vaul": {
              "dependent": "openops",
              "latest": "1.1.2",
              "wanted": "0.9.1"
            },
            "vite-plugin-dts": {
              "dependent": "openops",
              "latest": "4.5.4",
              "wanted": "4.5.4"
            },
            "write-file-atomic": {
              "dependent": "openops",
              "latest": "6.0.0",
              "wanted": "5.0.1"
            },
            "xml2js": {
              "dependent": "openops",
              "latest": "0.6.2",
              "wanted": "0.6.2"
            },
            "yaml": {
              "dependent": "openops",
              "latest": "2.8.1",
              "wanted": "2.4.1"
            },
            "zod": {
              "dependent": "openops",
              "latest": "4.1.9",
              "wanted": "4.0.14"
            },
            "zustand": {
              "dependent": "openops",
              "latest": "5.0.8",
              "wanted": "4.5.4"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "mcp-server-qdrant",
      "owner": "qdrant",
      "fullName": "qdrant/mcp-server-qdrant",
      "url": "https://github.com/qdrant/mcp-server-qdrant",
      "stars": 932,
      "description": "An official Qdrant Model Context Protocol (MCP) server implementation",
      "language": "Python",
      "updatedAt": "2025-09-18T11:48:31Z",
      "scanDate": "2025-09-19T02:25:49.335212+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "npcpy",
      "owner": "NPC-Worldwide",
      "fullName": "NPC-Worldwide/npcpy",
      "url": "https://github.com/NPC-Worldwide/npcpy",
      "stars": 926,
      "description": "The AI toolkit for the AI developer",
      "language": "Python",
      "updatedAt": "2025-09-18T16:59:12Z",
      "scanDate": "2025-09-19T02:25:50.751102+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 5
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcp-jetbrains",
      "owner": "JetBrains",
      "fullName": "JetBrains/mcp-jetbrains",
      "url": "https://github.com/JetBrains/mcp-jetbrains",
      "stars": 925,
      "description": "A model context protocol server to work with JetBrains IDEs: IntelliJ, PyCharm, WebStorm, etc. Also, works with Android Studio",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T11:48:33Z",
      "scanDate": "2025-09-19T02:25:53.806288+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "outdated": {
          "count": 2,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "mcp-jetbrains",
              "latest": "1.18.1",
              "wanted": "1.9.0"
            },
            "node-fetch": {
              "dependent": "mcp-jetbrains",
              "latest": "3.3.2",
              "wanted": "3.3.2"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "unreal-mcp",
      "owner": "chongdashu",
      "fullName": "chongdashu/unreal-mcp",
      "url": "https://github.com/chongdashu/unreal-mcp",
      "stars": 920,
      "description": "Enable AI assistant clients like Cursor, Windsurf and Claude Desktop to control Unreal Engine through natural language using the Model Context Protocol (MCP).",
      "language": "C++",
      "updatedAt": "2025-09-18T14:58:17Z",
      "scanDate": "2025-09-19T02:25:55.897065+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": false,
          "hasLinter": false,
          "hasTests": false,
          "score": 1
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "xiaozhi-esp32-server-java",
      "owner": "joey-zhou",
      "fullName": "joey-zhou/xiaozhi-esp32-server-java",
      "url": "https://github.com/joey-zhou/xiaozhi-esp32-server-java",
      "stars": 869,
      "description": "小智ESP32的Java企业级管理平台，提供设备监控、音色定制、角色切换和对话记录管理的前后端及服务端一体化解决方案",
      "language": "Java",
      "updatedAt": "2025-09-18T15:53:27Z",
      "scanDate": "2025-09-19T02:25:57.197821+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": true,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "MCP-Bridge",
      "owner": "SecretiveShell",
      "fullName": "SecretiveShell/MCP-Bridge",
      "url": "https://github.com/SecretiveShell/MCP-Bridge",
      "stars": 856,
      "description": "A middleware to provide an openAI compatible endpoint that can call MCP tools",
      "language": "Python",
      "updatedAt": "2025-09-18T11:53:42Z",
      "scanDate": "2025-09-19T02:26:23.04787+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "RedNote-MCP",
      "owner": "iFurySt",
      "fullName": "iFurySt/RedNote-MCP",
      "url": "https://github.com/iFurySt/RedNote-MCP",
      "stars": 825,
      "description": "🚀MCP server for accessing RedNote(XiaoHongShu, xhs).",
      "language": "TypeScript",
      "updatedAt": "2025-09-17T07:31:21Z",
      "scanDate": "2025-09-19T02:26:24.42708+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 1,
          "moderate": 0,
          "total": 1
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 2,
          "medium": 0,
          "total": 2,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            }
          ]
        },
        "outdated": {
          "count": 10,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "RedNote-MCP",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "@types/archiver": {
              "dependent": "RedNote-MCP",
              "latest": "6.0.3",
              "wanted": "6.0.3"
            },
            "archiver": {
              "dependent": "RedNote-MCP",
              "latest": "7.0.1",
              "wanted": "7.0.1"
            },
            "commander": {
              "dependent": "RedNote-MCP",
              "latest": "14.0.1",
              "wanted": "12.1.0"
            },
            "dotenv": {
              "dependent": "RedNote-MCP",
              "latest": "17.2.2",
              "wanted": "16.6.1"
            },
            "mcp-sdk": {
              "dependent": "RedNote-MCP",
              "latest": "0.1.0",
              "wanted": "0.1.0"
            },
            "playwright": {
              "dependent": "RedNote-MCP",
              "latest": "1.55.0",
              "wanted": "1.55.0"
            },
            "winston": {
              "dependent": "RedNote-MCP",
              "latest": "3.17.0",
              "wanted": "3.17.0"
            },
            "winston-daily-rotate-file": {
              "dependent": "RedNote-MCP",
              "latest": "5.0.0",
              "wanted": "5.0.0"
            },
            "zod": {
              "dependent": "RedNote-MCP",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "zen",
      "owner": "sheshbabu",
      "fullName": "sheshbabu/zen",
      "url": "https://github.com/sheshbabu/zen",
      "stars": 794,
      "description": "Selfhosted notes app. Single golang binary, notes stored as markdown within SQLite, full-text search, very low resource usage",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T15:37:05Z",
      "scanDate": "2025-09-19T02:26:31.220075+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 7,
          "total": 7,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2024-45341",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Usage of IPv6 zone IDs can bypass URI name constraints in crypto/x509"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-45336",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers incorrectly sent after cross-domain redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22866",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-22871",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Request smuggling due to acceptance of invalid chunked data in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-0913",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4673",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Sensitive headers not cleared on cross-origin redirect in net/http"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 71,
      "errors": []
    },
    {
      "name": "hyper-mcp",
      "owner": "tuananh",
      "fullName": "tuananh/hyper-mcp",
      "url": "https://github.com/tuananh/hyper-mcp",
      "stars": 788,
      "description": "📦️ A fast, secure MCP server that extends its capabilities through WebAssembly plugins.",
      "language": "Rust",
      "updatedAt": "2025-09-18T11:48:36Z",
      "scanDate": "2025-09-19T02:26:35.818795+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 5,
          "total": 5,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "RUSTSEC-2025-0057",
              "pkg": "fxhash",
              "severity": "MEDIUM",
              "title": "fxhash - no longer maintained"
            },
            {
              "fixedVersions": null,
              "id": "RUSTSEC-2024-0436",
              "pkg": "paste",
              "severity": "MEDIUM",
              "title": "paste - no longer maintained"
            },
            {
              "fixedVersions": null,
              "id": "RUSTSEC-2024-0370",
              "pkg": "proc-macro-error",
              "severity": "MEDIUM",
              "title": "proc-macro-error is unmaintained"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49092",
              "pkg": "rsa",
              "severity": "MEDIUM",
              "title": "Marvin Attack: potential key recovery through timing sidechannels"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53901",
              "pkg": "wasmtime",
              "severity": "MEDIUM",
              "title": "Host panic with `fd_renumber` WASIp1 function"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 83,
      "errors": []
    },
    {
      "name": "golf",
      "owner": "golf-mcp",
      "fullName": "golf-mcp/golf",
      "url": "https://github.com/golf-mcp/golf",
      "stars": 773,
      "description": "Production-Ready MCP Server Framework • Build, deploy \u0026 scale secure AI agent infrastructure • Includes Auth, Observability, Debugger, Telemetry \u0026 Runtime • Run real-world MCPs powering AI Agents ",
      "language": "Python",
      "updatedAt": "2025-09-18T11:48:39Z",
      "scanDate": "2025-09-19T02:26:45.82099+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "context-space",
      "owner": "context-space",
      "fullName": "context-space/context-space",
      "url": "https://github.com/context-space/context-space",
      "stars": 758,
      "description": "Ultimate Context Engineering Infrastructure, starting from MCPs and Integrations",
      "language": "Go",
      "updatedAt": "2025-09-18T17:09:53Z",
      "scanDate": "2025-09-19T02:26:47.157907+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "yokai",
      "owner": "ankorstore",
      "fullName": "ankorstore/yokai",
      "url": "https://github.com/ankorstore/yokai",
      "stars": 754,
      "description": "Simple, modular, and observable Go framework for backend applications.",
      "language": "Go",
      "updatedAt": "2025-09-17T18:21:12Z",
      "scanDate": "2025-09-19T02:26:48.915762+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "AI-Gateway",
      "owner": "Azure-Samples",
      "fullName": "Azure-Samples/AI-Gateway",
      "url": "https://github.com/Azure-Samples/AI-Gateway",
      "stars": 743,
      "description": "APIM ❤️ AI - This repo contains experiments on Azure API Management's AI capabilities, integrating with Azure OpenAI, AI Foundry, and much more 🚀 . New workshop experience at https://aka.ms/ai-gateway/workshop",
      "language": "Jupyter Notebook",
      "updatedAt": "2025-09-18T11:53:17Z",
      "scanDate": "2025-09-19T02:26:50.873296+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 4,
          "low": 0,
          "medium": 5,
          "total": 14,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2022-39327",
              "pkg": "azure-cli",
              "severity": "HIGH",
              "title": "Improper Control of Generation of Code ('Code Injection') in Azure CLI"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2022-39327",
              "pkg": "azure-cli",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-35255",
              "pkg": "azure-identity",
              "severity": "MODERATE",
              "title": "Azure Identity Libraries and Microsoft Authentication Library Elevation of Privilege Vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53366",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53365",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2020-13091",
              "pkg": "pandas",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1830",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Exposure of Sensitive Information to an Unauthorized Actor in Requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-35195",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests `Session` object does not verify requests after making first request with verify=False"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1829",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Exposure of Sensitive Information to an Unauthorized Actor in Requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-18074",
              "pkg": "requests",
              "severity": "HIGH",
              "title": "Insufficiently Protected Credentials in Requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1829",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2014-1830",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2018-18074",
              "pkg": "requests",
              "severity": "MEDIUM",
              "title": ""
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": true,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 47,
      "errors": []
    },
    {
      "name": "browser-use-mcp-server",
      "owner": "co-browser",
      "fullName": "co-browser/browser-use-mcp-server",
      "url": "https://github.com/co-browser/browser-use-mcp-server",
      "stars": 738,
      "description": "Browse the web, directly from Cursor etc.",
      "language": "Python",
      "updatedAt": "2025-09-18T11:48:41Z",
      "scanDate": "2025-09-19T02:27:00.169604+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcp-windbg",
      "owner": "svnscha",
      "fullName": "svnscha/mcp-windbg",
      "url": "https://github.com/svnscha/mcp-windbg",
      "stars": 736,
      "description": "Model Context Protocol for WinDBG",
      "language": "Python",
      "updatedAt": "2025-09-17T06:03:35Z",
      "scanDate": "2025-09-19T02:27:01.420865+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "kubectl-mcp-server",
      "owner": "rohitg00",
      "fullName": "rohitg00/kubectl-mcp-server",
      "url": "https://github.com/rohitg00/kubectl-mcp-server",
      "stars": 717,
      "description": "Chat with your Kubernetes Cluster using AI tools and IDEs like Claude and Cursor!",
      "language": "Python",
      "updatedAt": "2025-09-17T21:52:32Z",
      "scanDate": "2025-09-19T02:27:02.713451+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 7,
          "low": 2,
          "medium": 9,
          "total": 32,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2023-37276",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP request parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-23334",
              "pkg": "aiohttp",
              "severity": "HIGH",
              "title": "aiohttp is vulnerable to directory traversal"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-30251",
              "pkg": "aiohttp",
              "severity": "HIGH",
              "title": "aiohttp vulnerable to Denial of Service when trying to parse malformed POST requests"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-27306",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp Cross-site Scripting vulnerability on index pages for static file handling"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-52304",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp allows request smuggling due to incorrect parsing of chunk extensions"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-23829",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp's HTTP parser (the python one, not llhttp) still overly lenient about separators"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53643",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": " AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-47627",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "AIOHTTP has problems in HTTP parser (the python one, not llhttp)"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-pjjw-qhg8-p2p9",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp has vulnerable dependency that is vulnerable to request smuggling"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49081",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp's ClientSession is vulnerable to CRLF injection via version"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49082",
              "pkg": "aiohttp",
              "severity": "MODERATE",
              "title": "aiohttp's ClientSession is vulnerable to CRLF injection via method"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-37276",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": "aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP request parser"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-47627",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49081",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2023-49082",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-23334",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-23829",
              "pkg": "aiohttp",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-26130",
              "pkg": "cryptography",
              "severity": "HIGH",
              "title": "cryptography NULL pointer dereference with pkcs12.serialize_key_and_certificates when called with a non-matching certificate and private key and an hmac_hash override"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-12797",
              "pkg": "cryptography",
              "severity": "LOW",
              "title": "Vulnerable OpenSSL included in cryptography wheels"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-h4gh-qq45-vh27",
              "pkg": "cryptography",
              "severity": "MODERATE",
              "title": "pyca/cryptography has a vulnerable OpenSSL included in cryptography wheels"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-26130",
              "pkg": "cryptography",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-24762",
              "pkg": "fastapi",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53366",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53365",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-3772",
              "pkg": "pydantic",
              "severity": "MODERATE",
              "title": "Pydantic regular expression denial of service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-35195",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests `Session` object does not verify requests after making first request with verify=False"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47273",
              "pkg": "setuptools",
              "severity": "HIGH",
              "title": "setuptools has a path traversal vulnerability in PackageIndex.download that leads to Arbitrary File Write"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-6345",
              "pkg": "setuptools",
              "severity": "HIGH",
              "title": "setuptools vulnerable to Command Injection via package URL"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-47273",
              "pkg": "setuptools",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-37891",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50181",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 0,
      "errors": []
    },
    {
      "name": "agentic-radar",
      "owner": "splx-ai",
      "fullName": "splx-ai/agentic-radar",
      "url": "https://github.com/splx-ai/agentic-radar",
      "stars": 712,
      "description": "A security scanner for your LLM agentic workflows",
      "language": "Python",
      "updatedAt": "2025-09-18T05:41:28Z",
      "scanDate": "2025-09-19T02:27:11.991484+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 5,
          "low": 1,
          "medium": 1,
          "total": 14,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-53643",
              "pkg": "aiohttp",
              "severity": "LOW",
              "title": " AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57804",
              "pkg": "h2",
              "severity": "MODERATE",
              "title": "h2 allows HTTP Request Smuggling due to illegal characters in headers"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-6984",
              "pkg": "langchain-community",
              "severity": "HIGH",
              "title": "Langchain Community Vulnerable to XML External Entity (XXE) Attacks"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53366",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-53365",
              "pkg": "mcp",
              "severity": "HIGH",
              "title": "MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48379",
              "pkg": "pillow",
              "severity": "HIGH",
              "title": "Pillow vulnerability can cause write buffer overflow on BCn encoding"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-48379",
              "pkg": "pillow",
              "severity": "MEDIUM",
              "title": ""
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-4565",
              "pkg": "protobuf",
              "severity": "HIGH",
              "title": "protobuf-python has a potential Denial of Service issue"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-55197",
              "pkg": "pypdf",
              "severity": "MODERATE",
              "title": "PyPDF's Manipulated FlateDecode streams can exhaust RAM"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2024-47081",
              "pkg": "requests",
              "severity": "MODERATE",
              "title": "Requests vulnerable to .netrc credentials leak via malicious URLs"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54121",
              "pkg": "starlette",
              "severity": "MODERATE",
              "title": "Starlette has possible denial-of-service vector when parsing large files in multipart forms"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50182",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 does not control redirects in browsers and Node.js"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-50181",
              "pkg": "urllib3",
              "severity": "MODERATE",
              "title": "urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-54368",
              "pkg": "uv",
              "severity": "MODERATE",
              "title": "uv allows ZIP payload obfuscation through parsing differentials"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 5
        }
      },
      "securityScore": 53,
      "errors": []
    },
    {
      "name": "mcp-neo4j",
      "owner": "neo4j-contrib",
      "fullName": "neo4j-contrib/mcp-neo4j",
      "url": "https://github.com/neo4j-contrib/mcp-neo4j",
      "stars": 697,
      "description": "Model Context Protocol with Neo4j",
      "language": "Python",
      "updatedAt": "2025-09-18T11:48:31Z",
      "scanDate": "2025-09-19T02:27:17.05982+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mcp-memory-service",
      "owner": "doobidoo",
      "fullName": "doobidoo/mcp-memory-service",
      "url": "https://github.com/doobidoo/mcp-memory-service",
      "stars": 696,
      "description": " Universal MCP memory service with semantic search, multi-client support, and autonomous consolidation for Claude Desktop, VS Code, and 13+ AI   applications",
      "language": "Python",
      "updatedAt": "2025-09-18T12:27:03Z",
      "scanDate": "2025-09-19T02:27:18.773283+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "google_workspace_mcp",
      "owner": "taylorwilsdon",
      "fullName": "taylorwilsdon/google_workspace_mcp",
      "url": "https://github.com/taylorwilsdon/google_workspace_mcp",
      "stars": 683,
      "description": "Control Gmail, Google Calendar, Docs, Sheets, Slides, Chat, Forms, Tasks, Search \u0026 Drive with AI - Comprehensive Google Workspace / G Suite MCP Server",
      "language": "Python",
      "updatedAt": "2025-09-18T09:54:46Z",
      "scanDate": "2025-09-19T02:27:20.644997+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "slack-mcp-server",
      "owner": "korotovsky",
      "fullName": "korotovsky/slack-mcp-server",
      "url": "https://github.com/korotovsky/slack-mcp-server",
      "stars": 674,
      "description": "The most powerful MCP Slack Server with no permission requirements, Apps support, multiple transports Stdio and SSE, DMs, Group DMs and smart history fetch logic.",
      "language": "Go",
      "updatedAt": "2025-09-18T12:43:40Z",
      "scanDate": "2025-09-19T02:27:22.09243+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 1,
          "total": 1,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-47907",
              "pkg": "stdlib",
              "severity": "MEDIUM",
              "title": "Incorrect results returned from Rows.Scan in database/sql"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": true,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "jupyter-mcp-server",
      "owner": "datalayer",
      "fullName": "datalayer/jupyter-mcp-server",
      "url": "https://github.com/datalayer/jupyter-mcp-server",
      "stars": 668,
      "description": "🪐 ✨ Model Context Protocol (MCP) Server for Jupyter.",
      "language": "Jupyter Notebook",
      "updatedAt": "2025-09-17T21:41:32Z",
      "scanDate": "2025-09-19T02:27:29.183502+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "memory-bank-mcp",
      "owner": "alioshr",
      "fullName": "alioshr/memory-bank-mcp",
      "url": "https://github.com/alioshr/memory-bank-mcp",
      "stars": 666,
      "description": "A Model Context Protocol (MCP) server implementation for remote memory bank management, inspired by Cline Memory Bank.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T11:53:53Z",
      "scanDate": "2025-09-19T02:27:30.568787+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 1,
          "moderate": 1,
          "total": 2
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 3,
          "medium": 0,
          "total": 6,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-5889",
              "pkg": "brace-expansion",
              "severity": "LOW",
              "title": "brace-expansion Regular Expression Denial of Service vulnerability"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-31486",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite allows server.fs.deny to be bypassed with .svg or relative paths"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-32395",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite has an `server.fs.deny` bypass with an invalid `request-target`"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-46565",
              "pkg": "vite",
              "severity": "MODERATE",
              "title": "Vite's server.fs.deny bypassed with /. for files under project root"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 2,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "memory-bank-mcp",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "fs-extra": {
              "dependent": "memory-bank-mcp",
              "latest": "11.3.2",
              "wanted": "11.3.2"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 3
        }
      },
      "securityScore": 93,
      "errors": []
    },
    {
      "name": "VectorCode",
      "owner": "Davidyz",
      "fullName": "Davidyz/VectorCode",
      "url": "https://github.com/Davidyz/VectorCode",
      "stars": 659,
      "description": "A code repository indexing tool to supercharge your LLM experience.",
      "language": "Python",
      "updatedAt": "2025-09-18T11:53:48Z",
      "scanDate": "2025-09-19T02:27:36.902437+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "wassette",
      "owner": "microsoft",
      "fullName": "microsoft/wassette",
      "url": "https://github.com/microsoft/wassette",
      "stars": 649,
      "description": "Wassette: A security-oriented runtime that runs WebAssembly Components via MCP",
      "language": "Rust",
      "updatedAt": "2025-09-18T15:59:36Z",
      "scanDate": "2025-09-19T02:27:38.287939+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 2,
          "total": 2,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "RUSTSEC-2025-0057",
              "pkg": "fxhash",
              "severity": "MEDIUM",
              "title": "fxhash - no longer maintained"
            },
            {
              "fixedVersions": null,
              "id": "RUSTSEC-2024-0436",
              "pkg": "paste",
              "severity": "MEDIUM",
              "title": "paste - no longer maintained"
            }
          ]
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "better-chatbot",
      "owner": "cgoinglove",
      "fullName": "cgoinglove/better-chatbot",
      "url": "https://github.com/cgoinglove/better-chatbot",
      "stars": 634,
      "description": "Just a Better Chatbot. Powered by Agent \u0026 MCP \u0026 Workflows.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T14:26:06Z",
      "scanDate": "2025-09-19T02:27:50.195397+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 3,
          "medium": 0,
          "total": 8,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-49005",
              "pkg": "next",
              "severity": "LOW",
              "title": "Next.js has a Cache poisoning vulnerability due to omission of the Vary header"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57752",
              "pkg": "next",
              "severity": "MODERATE",
              "title": "Next.js Affected by Cache Key Confusion for Image Optimization API Routes"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-55173",
              "pkg": "next",
              "severity": "MODERATE",
              "title": "Next.js Content Injection Vulnerability for Image Optimization"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-57822",
              "pkg": "next",
              "severity": "MODERATE",
              "title": "Next.js Improper Middleware Redirect Handling Leads to SSRF"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 74,
          "packages": {
            "@ai-sdk/anthropic": {
              "dependent": "better-chatbot",
              "latest": "2.0.17",
              "wanted": "2.0.17"
            },
            "@ai-sdk/google": {
              "dependent": "better-chatbot",
              "latest": "2.0.14",
              "wanted": "2.0.14"
            },
            "@ai-sdk/openai": {
              "dependent": "better-chatbot",
              "latest": "2.0.32",
              "wanted": "2.0.32"
            },
            "@ai-sdk/openai-compatible": {
              "dependent": "better-chatbot",
              "latest": "1.0.18",
              "wanted": "1.0.18"
            },
            "@ai-sdk/react": {
              "dependent": "better-chatbot",
              "latest": "2.0.45",
              "wanted": "2.0.45"
            },
            "@ai-sdk/xai": {
              "dependent": "better-chatbot",
              "latest": "2.0.20",
              "wanted": "2.0.20"
            },
            "@modelcontextprotocol/sdk": {
              "dependent": "better-chatbot",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "@openrouter/ai-sdk-provider": {
              "dependent": "better-chatbot",
              "latest": "1.2.0",
              "wanted": "1.2.0"
            },
            "@radix-ui/react-accordion": {
              "dependent": "better-chatbot",
              "latest": "1.2.12",
              "wanted": "1.2.12"
            },
            "@radix-ui/react-avatar": {
              "dependent": "better-chatbot",
              "latest": "1.1.10",
              "wanted": "1.1.10"
            },
            "@radix-ui/react-checkbox": {
              "dependent": "better-chatbot",
              "latest": "1.3.3",
              "wanted": "1.3.3"
            },
            "@radix-ui/react-context-menu": {
              "dependent": "better-chatbot",
              "latest": "2.2.16",
              "wanted": "2.2.16"
            },
            "@radix-ui/react-dialog": {
              "dependent": "better-chatbot",
              "latest": "1.1.15",
              "wanted": "1.1.15"
            },
            "@radix-ui/react-dropdown-menu": {
              "dependent": "better-chatbot",
              "latest": "2.1.16",
              "wanted": "2.1.16"
            },
            "@radix-ui/react-hover-card": {
              "dependent": "better-chatbot",
              "latest": "1.1.15",
              "wanted": "1.1.15"
            },
            "@radix-ui/react-label": {
              "dependent": "better-chatbot",
              "latest": "2.1.7",
              "wanted": "2.1.7"
            },
            "@radix-ui/react-popover": {
              "dependent": "better-chatbot",
              "latest": "1.1.15",
              "wanted": "1.1.15"
            },
            "@radix-ui/react-radio-group": {
              "dependent": "better-chatbot",
              "latest": "1.3.8",
              "wanted": "1.3.8"
            },
            "@radix-ui/react-scroll-area": {
              "dependent": "better-chatbot",
              "latest": "1.2.10",
              "wanted": "1.2.10"
            },
            "@radix-ui/react-select": {
              "dependent": "better-chatbot",
              "latest": "2.2.6",
              "wanted": "2.2.6"
            },
            "@radix-ui/react-separator": {
              "dependent": "better-chatbot",
              "latest": "1.1.7",
              "wanted": "1.1.7"
            },
            "@radix-ui/react-slot": {
              "dependent": "better-chatbot",
              "latest": "1.2.3",
              "wanted": "1.2.3"
            },
            "@radix-ui/react-switch": {
              "dependent": "better-chatbot",
              "latest": "1.2.6",
              "wanted": "1.2.6"
            },
            "@radix-ui/react-tabs": {
              "dependent": "better-chatbot",
              "latest": "1.1.13",
              "wanted": "1.1.13"
            },
            "@radix-ui/react-toggle": {
              "dependent": "better-chatbot",
              "latest": "1.1.10",
              "wanted": "1.1.10"
            },
            "@radix-ui/react-tooltip": {
              "dependent": "better-chatbot",
              "latest": "1.2.8",
              "wanted": "1.2.8"
            },
            "@tiptap/extension-mention": {
              "dependent": "better-chatbot",
              "latest": "3.4.4",
              "wanted": "2.26.1"
            },
            "@tiptap/react": {
              "dependent": "better-chatbot",
              "latest": "3.4.4",
              "wanted": "2.26.1"
            },
            "@tiptap/starter-kit": {
              "dependent": "better-chatbot",
              "latest": "3.4.4",
              "wanted": "2.26.1"
            },
            "@tiptap/suggestion": {
              "dependent": "better-chatbot",
              "latest": "3.4.4",
              "wanted": "2.26.1"
            },
            "@xyflow/react": {
              "dependent": "better-chatbot",
              "latest": "12.8.5",
              "wanted": "12.8.5"
            },
            "ai": {
              "dependent": "better-chatbot",
              "latest": "5.0.45",
              "wanted": "5.0.45"
            },
            "bcrypt-ts": {
              "dependent": "better-chatbot",
              "latest": "7.1.0",
              "wanted": "7.1.0"
            },
            "better-auth": {
              "dependent": "better-chatbot",
              "latest": "1.3.12",
              "wanted": "1.3.12"
            },
            "chokidar": {
              "dependent": "better-chatbot",
              "latest": "4.0.3",
              "wanted": "4.0.3"
            },
            "class-variance-authority": {
              "dependent": "better-chatbot",
              "latest": "0.7.1",
              "wanted": "0.7.1"
            },
            "clsx": {
              "dependent": "better-chatbot",
              "latest": "2.1.1",
              "wanted": "2.1.1"
            },
            "cmdk": {
              "dependent": "better-chatbot",
              "latest": "1.1.1",
              "wanted": "1.1.1"
            },
            "consola": {
              "dependent": "better-chatbot",
              "latest": "3.4.2",
              "wanted": "3.4.2"
            },
            "date-fns": {
              "dependent": "better-chatbot",
              "latest": "4.1.0",
              "wanted": "4.1.0"
            },
            "deepmerge": {
              "dependent": "better-chatbot",
              "latest": "4.3.1",
              "wanted": "4.3.1"
            },
            "dotenv": {
              "dependent": "better-chatbot",
              "latest": "17.2.2",
              "wanted": "16.6.1"
            },
            "drizzle-orm": {
              "dependent": "better-chatbot",
              "latest": "0.44.5",
              "wanted": "0.41.0"
            },
            "emoji-picker-react": {
              "dependent": "better-chatbot",
              "latest": "4.13.3",
              "wanted": "4.13.3"
            },
            "framer-motion": {
              "dependent": "better-chatbot",
              "latest": "12.23.15",
              "wanted": "12.23.15"
            },
            "hast-util-to-jsx-runtime": {
              "dependent": "better-chatbot",
              "latest": "2.3.6",
              "wanted": "2.3.6"
            },
            "ioredis": {
              "dependent": "better-chatbot",
              "latest": "5.7.0",
              "wanted": "5.7.0"
            },
            "json-schema": {
              "dependent": "better-chatbot",
              "latest": "0.4.0",
              "wanted": "0.4.0"
            },
            "lucide-react": {
              "dependent": "better-chatbot",
              "latest": "0.544.0",
              "wanted": "0.486.0"
            },
            "mermaid": {
              "dependent": "better-chatbot",
              "latest": "11.12.0",
              "wanted": "11.12.0"
            },
            "nanoid": {
              "dependent": "better-chatbot",
              "latest": "5.1.5",
              "wanted": "5.1.5"
            },
            "next": {
              "dependent": "better-chatbot",
              "latest": "15.5.3",
              "wanted": "15.3.2"
            },
            "next-intl": {
              "dependent": "better-chatbot",
              "latest": "4.3.9",
              "wanted": "4.3.9"
            },
            "next-themes": {
              "dependent": "better-chatbot",
              "latest": "0.4.6",
              "wanted": "0.4.6"
            },
            "ogl": {
              "dependent": "better-chatbot",
              "latest": "1.0.11",
              "wanted": "1.0.11"
            },
            "ollama-ai-provider-v2": {
              "dependent": "better-chatbot",
              "latest": "1.3.1",
              "wanted": "1.3.1"
            },
            "pg": {
              "dependent": "better-chatbot",
              "latest": "8.16.3",
              "wanted": "8.16.3"
            },
            "react": {
              "dependent": "better-chatbot",
              "latest": "19.1.1",
              "wanted": "19.1.1"
            },
            "react-dom": {
              "dependent": "better-chatbot",
              "latest": "19.1.1",
              "wanted": "19.1.1"
            },
            "react-markdown": {
              "dependent": "better-chatbot",
              "latest": "10.1.0",
              "wanted": "10.1.0"
            },
            "react-resizable-panels": {
              "dependent": "better-chatbot",
              "latest": "3.0.6",
              "wanted": "2.1.9"
            },
            "recharts": {
              "dependent": "better-chatbot",
              "latest": "3.2.1",
              "wanted": "2.15.4"
            },
            "remark-gfm": {
              "dependent": "better-chatbot",
              "latest": "4.0.1",
              "wanted": "4.0.1"
            },
            "server-only": {
              "dependent": "better-chatbot",
              "latest": "0.0.1",
              "wanted": "0.0.1"
            },
            "shiki": {
              "dependent": "better-chatbot",
              "latest": "3.12.2",
              "wanted": "3.12.2"
            },
            "sonner": {
              "dependent": "better-chatbot",
              "latest": "2.0.7",
              "wanted": "2.0.7"
            },
            "swr": {
              "dependent": "better-chatbot",
              "latest": "2.3.6",
              "wanted": "2.3.6"
            },
            "tailwind-merge": {
              "dependent": "better-chatbot",
              "latest": "3.3.1",
              "wanted": "3.3.1"
            },
            "ts-edge": {
              "dependent": "better-chatbot",
              "latest": "1.0.4",
              "wanted": "1.0.4"
            },
            "ts-safe": {
              "dependent": "better-chatbot",
              "latest": "0.0.5",
              "wanted": "0.0.5"
            },
            "tw-animate-css": {
              "dependent": "better-chatbot",
              "latest": "1.3.8",
              "wanted": "1.3.8"
            },
            "vaul": {
              "dependent": "better-chatbot",
              "latest": "1.1.2",
              "wanted": "1.1.2"
            },
            "zod": {
              "dependent": "better-chatbot",
              "latest": "4.1.9",
              "wanted": "4.1.9"
            },
            "zustand": {
              "dependent": "better-chatbot",
              "latest": "5.0.8",
              "wanted": "5.0.8"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": true,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": true,
          "hasTests": true,
          "score": 6
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "mongodb-mcp-server",
      "owner": "mongodb-js",
      "fullName": "mongodb-js/mongodb-mcp-server",
      "url": "https://github.com/mongodb-js/mongodb-mcp-server",
      "stars": 633,
      "description": "A Model Context Protocol server to connect to MongoDB databases and MongoDB Atlas Clusters.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T07:47:01Z",
      "scanDate": "2025-09-19T02:28:05.500055+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 2,
          "moderate": 0,
          "total": 2
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 1,
          "medium": 0,
          "total": 1,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-9910",
              "pkg": "jsondiffpatch",
              "severity": "LOW",
              "title": "jsondiffpatch is vulnerable to Cross-site Scripting (XSS) via HtmlFormatter::nodeBegin"
            }
          ]
        },
        "outdated": {
          "count": 23,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "mongodb-mcp-server",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "@mongodb-js/device-id": {
              "dependent": "mongodb-mcp-server",
              "latest": "0.3.1",
              "wanted": "0.3.1"
            },
            "@mongodb-js/devtools-connect": {
              "dependent": "mongodb-mcp-server",
              "latest": "3.9.4",
              "wanted": "3.9.4"
            },
            "@mongodb-js/devtools-proxy-support": {
              "dependent": "mongodb-mcp-server",
              "latest": "0.5.3",
              "wanted": "0.5.3"
            },
            "@mongosh/arg-parser": {
              "dependent": "mongodb-mcp-server",
              "latest": "3.19.0",
              "wanted": "3.19.0"
            },
            "@mongosh/service-provider-node-driver": {
              "dependent": "mongodb-mcp-server",
              "latest": "3.17.0",
              "wanted": "3.12.0"
            },
            "@vitest/eslint-plugin": {
              "dependent": "mongodb-mcp-server",
              "latest": "1.3.12",
              "wanted": "1.3.12"
            },
            "bson": {
              "dependent": "mongodb-mcp-server",
              "latest": "6.10.4",
              "wanted": "6.10.4"
            },
            "express": {
              "dependent": "mongodb-mcp-server",
              "latest": "5.1.0",
              "wanted": "5.1.0"
            },
            "kerberos": {
              "dependent": "mongodb-mcp-server",
              "latest": "2.2.2",
              "wanted": "2.2.2"
            },
            "lru-cache": {
              "dependent": "mongodb-mcp-server",
              "latest": "11.2.1",
              "wanted": "11.2.1"
            },
            "mongodb": {
              "dependent": "mongodb-mcp-server",
              "latest": "6.20.0",
              "wanted": "6.20.0"
            },
            "mongodb-connection-string-url": {
              "dependent": "mongodb-mcp-server",
              "latest": "3.0.2",
              "wanted": "3.0.2"
            },
            "mongodb-log-writer": {
              "dependent": "mongodb-mcp-server",
              "latest": "2.4.1",
              "wanted": "2.4.1"
            },
            "mongodb-redact": {
              "dependent": "mongodb-mcp-server",
              "latest": "1.2.0",
              "wanted": "1.2.0"
            },
            "mongodb-schema": {
              "dependent": "mongodb-mcp-server",
              "latest": "12.6.2",
              "wanted": "12.6.2"
            },
            "node-fetch": {
              "dependent": "mongodb-mcp-server",
              "latest": "3.3.2",
              "wanted": "3.3.2"
            },
            "node-machine-id": {
              "dependent": "mongodb-mcp-server",
              "latest": "1.1.12",
              "wanted": "1.1.12"
            },
            "oauth4webapi": {
              "dependent": "mongodb-mcp-server",
              "latest": "3.8.1",
              "wanted": "3.8.1"
            },
            "openapi-fetch": {
              "dependent": "mongodb-mcp-server",
              "latest": "0.14.0",
              "wanted": "0.14.0"
            },
            "ts-levenshtein": {
              "dependent": "mongodb-mcp-server",
              "latest": "1.0.7",
              "wanted": "1.0.7"
            },
            "yargs-parser": {
              "dependent": "mongodb-mcp-server",
              "latest": "22.0.0",
              "wanted": "21.1.1"
            },
            "zod": {
              "dependent": "mongodb-mcp-server",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": true,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "phpMyFAQ",
      "owner": "thorsten",
      "fullName": "thorsten/phpMyFAQ",
      "url": "https://github.com/thorsten/phpMyFAQ",
      "stars": 600,
      "description": "phpMyFAQ - Open Source FAQ web application for PHP 8.3+ and MySQL, PostgreSQL and other databases",
      "language": "PHP",
      "updatedAt": "2025-09-18T05:29:30Z",
      "scanDate": "2025-09-19T02:28:21.171728+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "outdated": {
          "count": 13,
          "packages": {
            "@popperjs/core": {
              "dependent": "phpMyFAQ",
              "latest": "2.11.8",
              "wanted": "2.11.8"
            },
            "autocompleter": {
              "dependent": "phpMyFAQ",
              "latest": "9.3.2",
              "wanted": "9.3.2"
            },
            "bootstrap": {
              "dependent": "phpMyFAQ",
              "latest": "5.3.8",
              "wanted": "5.3.8"
            },
            "bootstrap-datepicker": {
              "dependent": "phpMyFAQ",
              "latest": "1.10.1",
              "wanted": "1.10.1"
            },
            "bootstrap-icons": {
              "dependent": "phpMyFAQ",
              "latest": "1.13.1",
              "wanted": "1.13.1"
            },
            "chart.js": {
              "dependent": "phpMyFAQ",
              "latest": "4.5.0",
              "wanted": "4.5.0"
            },
            "choices.js": {
              "dependent": "phpMyFAQ",
              "latest": "11.1.0",
              "wanted": "11.1.0"
            },
            "handlebars": {
              "dependent": "phpMyFAQ",
              "latest": "4.7.8",
              "wanted": "4.7.8"
            },
            "highlight.js": {
              "dependent": "phpMyFAQ",
              "latest": "11.11.1",
              "wanted": "11.11.1"
            },
            "jodit": {
              "dependent": "phpMyFAQ",
              "latest": "4.6.6",
              "wanted": "4.6.6"
            },
            "masonry-layout": {
              "dependent": "phpMyFAQ",
              "latest": "4.2.2",
              "wanted": "4.2.2"
            },
            "sortablejs": {
              "dependent": "phpMyFAQ",
              "latest": "1.15.6",
              "wanted": "1.15.6"
            },
            "vanilla-cookieconsent": {
              "dependent": "phpMyFAQ",
              "latest": "3.1.0",
              "wanted": "3.1.0"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": true,
        "hasDependabot": true,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": true,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "ros-mcp-server",
      "owner": "robotmcp",
      "fullName": "robotmcp/ros-mcp-server",
      "url": "https://github.com/robotmcp/ros-mcp-server",
      "stars": 596,
      "description": "Connect AI models like Claude \u0026 GPT with robots using MCP and ROS.",
      "language": "Python",
      "updatedAt": "2025-09-18T16:05:14Z",
      "scanDate": "2025-09-19T02:28:29.788788+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "bifrost",
      "owner": "maximhq",
      "fullName": "maximhq/bifrost",
      "url": "https://github.com/maximhq/bifrost",
      "stars": 578,
      "description": "The Fastest LLM Gateway with built in OTel observability and MCP gateway",
      "language": "Go",
      "updatedAt": "2025-09-18T16:07:24Z",
      "scanDate": "2025-09-19T02:28:36.147911+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "wcgw",
      "owner": "rusiaaman",
      "fullName": "rusiaaman/wcgw",
      "url": "https://github.com/rusiaaman/wcgw",
      "stars": 577,
      "description": "Shell and coding agent on claude desktop app",
      "language": "Python",
      "updatedAt": "2025-09-18T14:36:02Z",
      "scanDate": "2025-09-19T02:28:47.470833+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "ref-tools-mcp",
      "owner": "ref-tools",
      "fullName": "ref-tools/ref-tools-mcp",
      "url": "https://github.com/ref-tools/ref-tools-mcp",
      "stars": 576,
      "description": "An MCP server to stop hallucinations with token efficient search over public and private documentation.",
      "language": "TypeScript",
      "updatedAt": "2025-09-18T15:09:25Z",
      "scanDate": "2025-09-19T02:28:50.553095+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 1,
          "high": 2,
          "info": 0,
          "low": 0,
          "moderate": 1,
          "total": 4
        },
        "osv": {
          "critical": 1,
          "high": 2,
          "low": 0,
          "medium": 0,
          "total": 4,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58444",
              "pkg": "@modelcontextprotocol/inspector",
              "severity": "HIGH",
              "title": "MCP Inspector is Vulnerable to Potential Command Execution via XSS When Connecting to an Untrusted MCP Server"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            },
            {
              "fixedVersions": null,
              "id": "GHSA-67mh-4wv8-2f99",
              "pkg": "esbuild",
              "severity": "MODERATE",
              "title": "esbuild enables any website to send any requests to the development server and read the response"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-7783",
              "pkg": "form-data",
              "severity": "CRITICAL",
              "title": "form-data uses unsafe random function in form-data for choosing boundary"
            }
          ]
        },
        "outdated": {
          "count": 3,
          "packages": {
            "@modelcontextprotocol/inspector": {
              "dependent": "ref-tools-mcp",
              "latest": "0.16.7",
              "wanted": "0.16.7"
            },
            "@modelcontextprotocol/sdk": {
              "dependent": "ref-tools-mcp",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "axios": {
              "dependent": "ref-tools-mcp",
              "latest": "1.12.2",
              "wanted": "1.12.2"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 29,
      "errors": []
    },
    {
      "name": "GalwayBus",
      "owner": "joreilly",
      "fullName": "joreilly/GalwayBus",
      "url": "https://github.com/joreilly/GalwayBus",
      "stars": 571,
      "description": "Galway Bus Kotlin Multiplatform project using Jetpack Compose and SwiftUI ",
      "language": "Kotlin",
      "updatedAt": "2025-09-09T20:32:41Z",
      "scanDate": "2025-09-19T02:28:56.30476+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "12306-mcp",
      "owner": "Joooook",
      "fullName": "Joooook/12306-mcp",
      "url": "https://github.com/Joooook/12306-mcp",
      "stars": 569,
      "description": "This is a 12306 ticket search server based on the Model Context Protocol (MCP).",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T11:26:53Z",
      "scanDate": "2025-09-19T02:28:57.710077+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 2,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 2
        },
        "osv": {
          "critical": 0,
          "high": 2,
          "low": 0,
          "medium": 0,
          "total": 2,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58444",
              "pkg": "@modelcontextprotocol/inspector",
              "severity": "HIGH",
              "title": "MCP Inspector is Vulnerable to Potential Command Execution via XSS When Connecting to an Untrusted MCP Server"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58754",
              "pkg": "axios",
              "severity": "HIGH",
              "title": "Axios is vulnerable to DoS attack through lack of data size check"
            }
          ]
        },
        "outdated": {
          "count": 8,
          "packages": {
            "@modelcontextprotocol/inspector": {
              "dependent": "12306-mcp",
              "latest": "0.16.7",
              "wanted": "0.16.7"
            },
            "@modelcontextprotocol/sdk": {
              "dependent": "12306-mcp",
              "latest": "1.18.1",
              "wanted": "1.18.1"
            },
            "axios": {
              "dependent": "12306-mcp",
              "latest": "1.12.2",
              "wanted": "1.12.2"
            },
            "commander": {
              "dependent": "12306-mcp",
              "latest": "14.0.1",
              "wanted": "14.0.1"
            },
            "date-fns": {
              "dependent": "12306-mcp",
              "latest": "4.1.0",
              "wanted": "4.1.0"
            },
            "date-fns-tz": {
              "dependent": "12306-mcp",
              "latest": "3.2.0",
              "wanted": "3.2.0"
            },
            "mcp-http-server": {
              "dependent": "12306-mcp",
              "latest": "1.2.4",
              "wanted": "1.2.4"
            },
            "zod": {
              "dependent": "12306-mcp",
              "latest": "4.1.9",
              "wanted": "3.25.76"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": false,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 2
        }
      },
      "securityScore": 64,
      "errors": []
    },
    {
      "name": "wenyan-mcp",
      "owner": "caol64",
      "fullName": "caol64/wenyan-mcp",
      "url": "https://github.com/caol64/wenyan-mcp",
      "stars": 559,
      "description": "文颜 MCP Server 可以让 AI 自动将 Markdown 文章排版后发布至微信公众号。",
      "language": "JavaScript",
      "updatedAt": "2025-09-18T14:09:50Z",
      "scanDate": "2025-09-19T02:29:03.258377+09:00",
      "vulnerabilities": {
        "npmAudit": {
          "critical": 0,
          "high": 0,
          "info": 0,
          "low": 0,
          "moderate": 0,
          "total": 0
        },
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 2,
          "medium": 0,
          "total": 2,
          "vulnerabilities": [
            {
              "fixedVersions": null,
              "id": "CVE-2025-58751",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite middleware may serve files starting with the same name with the public directory"
            },
            {
              "fixedVersions": null,
              "id": "CVE-2025-58752",
              "pkg": "vite",
              "severity": "LOW",
              "title": "Vite's `server.fs` settings were not applied to HTML files"
            }
          ]
        },
        "outdated": {
          "count": 2,
          "packages": {
            "@modelcontextprotocol/sdk": {
              "dependent": "wenyan-mcp",
              "latest": "1.18.1",
              "wanted": "0.6.0"
            },
            "@wenyan-md/core": {
              "dependent": "wenyan-mcp",
              "latest": "1.0.11",
              "wanted": "1.0.11"
            }
          }
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": true,
        "hasPackageLock": true,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": true,
          "score": 4
        }
      },
      "securityScore": 100,
      "errors": []
    },
    {
      "name": "FantasyPremierLeague",
      "owner": "joreilly",
      "fullName": "joreilly/FantasyPremierLeague",
      "url": "https://github.com/joreilly/FantasyPremierLeague",
      "stars": 558,
      "description": "Fantasy Premier League Kotlin Multiplatform sample using Jetpack Compose, Compose for Desktop and SwiftUI (and Room for local persistence)",
      "language": "Jupyter Notebook",
      "updatedAt": "2025-09-10T20:38:19Z",
      "scanDate": "2025-09-19T02:29:09.695891+09:00",
      "vulnerabilities": {
        "osv": {
          "critical": 0,
          "high": 0,
          "low": 0,
          "medium": 0,
          "total": 0,
          "vulnerabilities": []
        },
        "secrets": {
          "secrets": [],
          "secretsFound": 0
        }
      },
      "checks": {
        "hasCodeQL": false,
        "hasDependabot": false,
        "hasGoMod": false,
        "hasPackageJson": false,
        "hasPackageLock": false,
        "hasSecretScanning": false,
        "hasSecurityPolicy": false,
        "securityPractices": {
          "hasCI": true,
          "hasEnvExample": false,
          "hasGitignore": true,
          "hasLicense": true,
          "hasLinter": false,
          "hasTests": false,
          "score": 3
        }
      },
      "securityScore": 100,
      "errors": []
    }
  ]
};