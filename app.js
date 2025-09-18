let servers = window.scanData.servers;
let displayedServers = [...servers];
let filteredServers = [...servers];
let currentPage = 1;
const itemsPerPage = 10;

// Modal handling
const modal = document.getElementById('serverModal');
const modalBody = document.getElementById('modalBody');
const closeBtn = document.getElementsByClassName('close')[0];
const infoModal = document.getElementById('infoModal');
const infoModalBody = document.getElementById('infoModalBody');
const closeInfoBtn = document.getElementsByClassName('close-info')[0];
const shareModal = document.getElementById('shareModal');
const closeShareBtn = document.getElementsByClassName('close-share')[0];

closeBtn.onclick = function() {
    modal.style.display = "none";
}

closeInfoBtn.onclick = function() {
    infoModal.style.display = "none";
}

closeShareBtn.onclick = function() {
    shareModal.style.display = "none";
}

window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
    if (event.target == infoModal) {
        infoModal.style.display = "none";
    }
    if (event.target == shareModal) {
        shareModal.style.display = "none";
    }
}

// Security terms explanations
const securityTerms = {
    vulnerabilities: {
        title: "Vulnerability Severity Levels",
        items: [
            {
                name: "CRITICAL",
                badge: "critical",
                description: "Vulnerabilities that can be easily exploited and lead to system compromise, data breach, or service disruption. Immediate action required. (Score impact: -15 points per vulnerability)"
            },
            {
                name: "HIGH",
                badge: "high",
                description: "Serious vulnerabilities that could lead to unauthorized access or significant impact. Should be fixed promptly. (Score impact: -10 points per vulnerability)"
            },
            {
                name: "MEDIUM",
                badge: "medium",
                description: "Moderate risk vulnerabilities that require specific conditions to exploit. Plan to fix in regular updates. (Score impact: -5 points per vulnerability)"
            },
            {
                name: "LOW",
                badge: "low",
                description: "Minor issues with minimal impact. Fix when convenient or during regular maintenance. (Score impact: -2 points per vulnerability)"
            }
        ]
    },
    securityFeatures: {
        title: "Security Features",
        items: [
            {
                name: "Security Policy",
                icon: "fas fa-shield-alt",
                description: "A SECURITY.md file that provides vulnerability disclosure guidelines and security contact information. Shows commitment to security. (Score bonus: +2 points)"
            },
            {
                name: "Dependabot",
                icon: "fas fa-robot",
                description: "GitHub's automated dependency update service that monitors and updates vulnerable dependencies automatically. (Score bonus: +3 points)"
            },
            {
                name: "CodeQL",
                icon: "fas fa-code",
                description: "GitHub's semantic code analysis engine that finds security vulnerabilities in code before they reach production. (Score bonus: +3 points)"
            }
        ]
    },
    developmentPractices: {
        title: "Development Best Practices",
        items: [
            {
                name: "Tests",
                icon: "fas fa-vial",
                description: "Automated testing ensures code quality and prevents regressions. Indicates mature development practices."
            },
            {
                name: "CI/CD",
                icon: "fas fa-sync-alt",
                description: "Continuous Integration/Deployment automates building, testing, and deployment, reducing human error."
            },
            {
                name: "Linter",
                icon: "fas fa-check-double",
                description: "Code linting tools enforce consistent code style and catch potential bugs early."
            },
            {
                name: "License",
                icon: "fas fa-certificate",
                description: "Clear licensing terms help users understand how they can use and contribute to the project."
            },
            {
                name: ".gitignore",
                icon: "fas fa-eye-slash",
                description: "Prevents sensitive files and build artifacts from being accidentally committed to the repository."
            },
            {
                name: ".env.example",
                icon: "fas fa-file-alt",
                description: "Template for environment variables helps developers set up the project without exposing secrets."
            }
        ]
    },
    scoring: {
        title: "Security Score Calculation",
        items: [
            {
                name: "Base Score",
                description: "Every project starts with 100 points"
            },
            {
                name: "Deductions",
                description: "Points are deducted based on vulnerability severity: Critical (-15), High (-10), Medium (-5), Low (-2)"
            },
            {
                name: "Bonuses",
                description: "Points added for security features: Dependabot (+3), CodeQL (+3), Security Policy (+2), Development practices (+2 per practice)"
            },
            {
                name: "Final Score",
                description: "Base score minus deductions plus bonuses (minimum 0, maximum 100)"
            }
        ]
    }
};

function showInfoModal(section) {
    let content = '<div class="term-sections">';
    
    if (section) {
        // Show specific section
        const sectionData = securityTerms[section];
        if (sectionData) {
            content += generateTermSection(sectionData);
        }
    } else {
        // Show all sections
        for (const [key, sectionData] of Object.entries(securityTerms)) {
            content += generateTermSection(sectionData);
        }
    }
    
    content += '</div>';
    infoModalBody.innerHTML = content;
    infoModal.style.display = "block";
}

function generateTermSection(sectionData) {
    let html = `<div class="term-section">
        <h3>${sectionData.title}</h3>`;
    
    sectionData.items.forEach(item => {
        html += `<div class="term-item">
            <h4>`;
        
        if (item.badge) {
            html += `<span class="term-badge ${item.badge}">${item.name}</span>`;
        } else if (item.icon) {
            html += `<i class="${item.icon}"></i> ${item.name}`;
        } else {
            html += item.name;
        }
        
        html += `</h4>
            <p>${item.description}</p>
        </div>`;
    });
    
    html += '</div>';
    return html;
}

function showServerDetails(server) {
    const modalContent = generateDetailedView(server);
    modalBody.innerHTML = modalContent;
    modal.style.display = "block";
}

function generateDetailedView(server) {
    const scoreBreakdown = calculateScoreBreakdown(server);
    const vulnList = generateVulnerabilityList(server);
    
    return `
        <h2>${server.owner}/${server.name}</h2>
        <p class="server-description">${server.description || 'No description'}</p>
        
        <div class="server-meta" style="margin: 1rem 0;">
            <span class="stars"><i class="fas fa-star"></i> ${server.stars}</span>
            ${server.language ? `<span class="language">${server.language}</span>` : ''}
            <a href="${server.url}" target="_blank"><i class="fas fa-external-link-alt"></i> View on GitHub</a>
        </div>
        
        <h3>Security Score: ${server.securityScore}/100</h3>
        <div class="score-breakdown">
            <h4>Score Calculation:</h4>
            <div class="score-details">
                ${scoreBreakdown}
            </div>
        </div>
        
        ${vulnList}
        
        <h3 style="margin-top: 1.5rem;">Security Checks</h3>
        ${generateSecurityChecksDetail(server.checks)}
    `;
}

function calculateScoreBreakdown(server) {
    let breakdown = [];
    let baseScore = 100;
    
    // Vulnerability deductions
    if (server.vulnerabilities?.osv) {
        const osv = server.vulnerabilities.osv;
        if (osv.critical > 0) breakdown.push(`<div class="score-item negative"><span>Critical vulns (${osv.critical})</span><span>-${osv.critical * 15}</span></div>`);
        if (osv.high > 0) breakdown.push(`<div class="score-item negative"><span>High vulns (${osv.high})</span><span>-${osv.high * 10}</span></div>`);
        if (osv.medium > 0) breakdown.push(`<div class="score-item negative"><span>Medium vulns (${osv.medium})</span><span>-${osv.medium * 5}</span></div>`);
        if (osv.low > 0) breakdown.push(`<div class="score-item negative"><span>Low vulns (${osv.low})</span><span>-${osv.low * 2}</span></div>`);
    }
    
    if (server.vulnerabilities?.npmAudit) {
        const audit = server.vulnerabilities.npmAudit;
        if (audit.critical > 0) breakdown.push(`<div class="score-item negative"><span>NPM critical (${audit.critical})</span><span>-${audit.critical * 15}</span></div>`);
        if (audit.high > 0) breakdown.push(`<div class="score-item negative"><span>NPM high (${audit.high})</span><span>-${audit.high * 10}</span></div>`);
        if (audit.moderate > 0) breakdown.push(`<div class="score-item negative"><span>NPM moderate (${audit.moderate})</span><span>-${audit.moderate * 5}</span></div>`);
        if (audit.low > 0) breakdown.push(`<div class="score-item negative"><span>NPM low (${audit.low})</span><span>-${audit.low * 2}</span></div>`);
    }
    
    // Security practice bonuses
    if (server.checks?.securityPractices) {
        const practices = server.checks.securityPractices;
        const score = practices.score || 0;
        if (score > 0) breakdown.push(`<div class="score-item positive"><span>Security practices (${score})</span><span>+${score * 2}</span></div>`);
    }
    
    if (server.checks?.hasDependabot) breakdown.push(`<div class="score-item positive"><span>Dependabot enabled</span><span>+3</span></div>`);
    if (server.checks?.hasCodeQL) breakdown.push(`<div class="score-item positive"><span>CodeQL enabled</span><span>+3</span></div>`);
    if (server.checks?.hasSecurityPolicy) breakdown.push(`<div class="score-item positive"><span>Security policy</span><span>+2</span></div>`);
    
    if (breakdown.length === 0) {
        breakdown.push(`<div class="score-item"><span>Base score</span><span>100</span></div>`);
    }
    
    return breakdown.join('');
}

function generateVulnerabilityList(server) {
    let html = '';
    
    if (server.vulnerabilities?.osv?.vulnerabilities && server.vulnerabilities.osv.vulnerabilities.length > 0) {
        html += `
            <div class="vuln-list">
                <h3>Vulnerabilities Found (${server.vulnerabilities.osv.total})</h3>
        `;
        
        server.vulnerabilities.osv.vulnerabilities.forEach(vuln => {
            const severityClass = vuln.severity.toLowerCase();
            // Generate appropriate link based on vulnerability ID format
            let vulnLink = '';
            if (vuln.id.startsWith('GHSA-')) {
                // GitHub Security Advisory
                vulnLink = `https://github.com/advisories/${vuln.id}`;
            } else if (vuln.id.startsWith('CVE-')) {
                // CVE Database
                vulnLink = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.id}`;
            } else if (vuln.id.startsWith('SNYK-')) {
                // Snyk vulnerability database
                vulnLink = `https://security.snyk.io/vuln/${vuln.id}`;
            } else if (vuln.id.startsWith('NPM-')) {
                // NPM advisory
                const npmId = vuln.id.replace('NPM-', '');
                vulnLink = `https://www.npmjs.com/advisories/${npmId}`;
            } else {
                // Default to OSV database
                vulnLink = `https://osv.dev/vulnerability/${vuln.id}`;
            }
            
            html += `
                <div class="vuln-detail ${severityClass}">
                    <div class="vuln-id">
                        <a href="${vulnLink}" target="_blank" rel="noopener noreferrer" 
                           style="color: var(--primary-color); text-decoration: none; font-weight: bold;"
                           onmouseover="this.style.textDecoration='underline'" 
                           onmouseout="this.style.textDecoration='none'">
                            ${vuln.id} <i class="fas fa-external-link-alt" style="font-size: 0.8em; margin-left: 4px;"></i>
                        </a>
                    </div>
                    <div class="vuln-package">Package: ${vuln.pkg}</div>
                    ${vuln.title ? `<div>${vuln.title}</div>` : ''}
                    <div><span class="vuln-badge ${severityClass}">${vuln.severity}</span></div>
                </div>
            `;
        });
        
        html += '</div>';
    }
    
    return html;
}

function generateSecurityChecksDetail(checks) {
    if (!checks) return '<p>No security checks data available</p>';
    
    let items = [];
    
    // Main security features
    items.push(`<h4>Security Features:</h4>`);
    items.push(`<div class="checks">`);
    items.push(checks.hasSecurityPolicy ? 
        `<span class="check-item success"><i class="fas fa-check"></i> Security Policy</span>` :
        `<span class="check-item warning"><i class="fas fa-times"></i> No Security Policy</span>`);
    
    items.push(checks.hasDependabot ? 
        `<span class="check-item success"><i class="fas fa-check"></i> Dependabot</span>` :
        `<span class="check-item warning"><i class="fas fa-times"></i> No Dependabot</span>`);
    
    items.push(checks.hasCodeQL ? 
        `<span class="check-item success"><i class="fas fa-check"></i> CodeQL</span>` :
        `<span class="check-item warning"><i class="fas fa-times"></i> No CodeQL</span>`);
    items.push(`</div>`);
    
    // Development practices
    if (checks.securityPractices) {
        const practices = checks.securityPractices;
        items.push(`<h4 style="margin-top: 1rem;">Development Practices:</h4>`);
        items.push(`<div class="checks">`);
        
        if (practices.hasTests) items.push(`<span class="check-item success"><i class="fas fa-check"></i> Tests</span>`);
        if (practices.hasCI) items.push(`<span class="check-item success"><i class="fas fa-check"></i> CI/CD</span>`);
        if (practices.hasLinter) items.push(`<span class="check-item success"><i class="fas fa-check"></i> Linter</span>`);
        if (practices.hasLicense) items.push(`<span class="check-item success"><i class="fas fa-check"></i> License</span>`);
        if (practices.hasGitignore) items.push(`<span class="check-item success"><i class="fas fa-check"></i> .gitignore</span>`);
        if (practices.hasEnvExample) items.push(`<span class="check-item success"><i class="fas fa-check"></i> .env.example</span>`);
        
        items.push(`</div>`);
        items.push(`<p style="margin-top: 0.5rem;">Practice Score: ${practices.score}/6</p>`);
    }
    
    // Package management
    items.push(`<h4 style="margin-top: 1rem;">Package Management:</h4>`);
    items.push(`<div class="checks">`);
    if (checks.hasPackageJson) items.push(`<span class="check-item success"><i class="fas fa-check"></i> package.json</span>`);
    if (checks.hasPackageLock) items.push(`<span class="check-item success"><i class="fas fa-check"></i> Lock file</span>`);
    if (checks.hasGoMod) items.push(`<span class="check-item success"><i class="fas fa-check"></i> go.mod</span>`);
    items.push(`</div>`);
    
    return items.join('');
}

function renderServers() {
    const container = document.getElementById('serverList');
    container.innerHTML = '';
    
    // Calculate pagination
    const totalItems = displayedServers.length;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, totalItems);
    const pageServers = displayedServers.slice(startIndex, endIndex);
    
    let totalCritical = 0, totalHigh = 0, secureCount = 0;
    
    // Calculate stats for ALL servers (not just current page)
    displayedServers.forEach(server => {
        const vulns = server.vulnerabilities?.osv || {};
        totalCritical += vulns.critical || 0;
        totalHigh += vulns.high || 0;
        
        if (server.securityScore >= 80) {
            secureCount++;
        }
    });
    
    // Render only current page servers
    pageServers.forEach(server => {
        const card = createServerCard(server);
        container.appendChild(card);
    });
    
    document.getElementById('totalCritical').textContent = totalCritical;
    document.getElementById('totalHigh').textContent = totalHigh;
    document.getElementById('secureServers').textContent = secureCount;
    
    // Render pagination controls
    renderPagination(totalPages);
}

function renderPagination(totalPages) {
    const paginationContainer = document.getElementById('pagination');
    if (totalPages <= 1) {
        paginationContainer.innerHTML = '';
        return;
    }
    
    let html = '';
    
    // Previous button
    html += `<button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>
        <i class="fas fa-chevron-left"></i> Previous
    </button>`;
    
    // Page numbers
    html += '<div class="page-numbers">';
    
    // Show first page
    if (currentPage > 3) {
        html += `<button onclick="changePage(1)">1</button>`;
        if (currentPage > 4) {
            html += `<span class="page-info">...</span>`;
        }
    }
    
    // Show pages around current page
    for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
        html += `<button onclick="changePage(${i})" ${i === currentPage ? 'class="active"' : ''}>${i}</button>`;
    }
    
    // Show last page
    if (currentPage < totalPages - 2) {
        if (currentPage < totalPages - 3) {
            html += `<span class="page-info">...</span>`;
        }
        html += `<button onclick="changePage(${totalPages})">${totalPages}</button>`;
    }
    
    html += '</div>';
    
    // Next button
    html += `<button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>
        Next <i class="fas fa-chevron-right"></i>
    </button>`;
    
    // Page info
    html += `<span class="page-info">Page ${currentPage} of ${totalPages}</span>`;
    
    paginationContainer.innerHTML = html;
}

function changePage(page) {
    const totalPages = Math.ceil(displayedServers.length / itemsPerPage);
    if (page >= 1 && page <= totalPages) {
        currentPage = page;
        renderServers();
        // Scroll to top of list
        document.getElementById('serverList').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

function createServerCard(server) {
    const card = document.createElement('div');
    card.className = 'server-card';
    card.onclick = () => showServerDetails(server);
    
    const scoreColor = getScoreColor(server.securityScore);
    const vulns = server.vulnerabilities?.osv || {};
    const scoreBreakdown = generateScoreBreakdownSummary(server);
    
    card.innerHTML = `
        <div class="server-header">
            <div class="server-info">
                <h2><a href="${server.url}" target="_blank" onclick="event.stopPropagation()">${server.owner}/${server.name}</a></h2>
                <div class="server-description">${server.description || 'No description available'}</div>
                <div class="server-meta">
                    <div class="stars">
                        <i class="fas fa-star"></i>
                        <span>${server.stars}</span>
                    </div>
                    ${server.language ? `<span class="language">${server.language}</span>` : ''}
                </div>
            </div>
            <div class="security-score">
                <div class="score-circle">
                    <svg width="80" height="80">
                        <circle cx="40" cy="40" r="35" stroke="#e0e0e0" stroke-width="5" fill="none"/>
                        <circle cx="40" cy="40" r="35" stroke="${scoreColor}" stroke-width="5" fill="none"
                                stroke-dasharray="${server.securityScore * 2.2} 220"
                                stroke-dashoffset="0"
                                transform="rotate(-90 40 40)"/>
                    </svg>
                    <div class="score-value" style="color: ${scoreColor}">${server.securityScore}</div>
                </div>
                <div class="score-label">
                    Security Score
                    <i class="fas fa-info-circle info-icon" onclick="event.stopPropagation(); showInfoModal('scoring')" title="How is this calculated?"></i>
                </div>
            </div>
        </div>
        
        ${renderVulnerabilities(vulns)}
        ${renderChecks(server.checks)}
        ${scoreBreakdown}
        
        <div class="view-details">
            <button class="btn-details" onclick="event.stopPropagation(); showServerDetails(${JSON.stringify(server).replace(/"/g, '&quot;')})">
                <i class="fas fa-info-circle"></i> View Details
            </button>
        </div>
        
        ${renderErrors(server.errors)}
    `;
    
    return card;
}

function generateScoreBreakdownSummary(server) {
    let deductions = 0;
    let additions = 0;
    
    if (server.vulnerabilities?.osv) {
        const osv = server.vulnerabilities.osv;
        deductions += (osv.critical || 0) * 15;
        deductions += (osv.high || 0) * 10;
        deductions += (osv.medium || 0) * 5;
        deductions += (osv.low || 0) * 2;
    }
    
    if (server.vulnerabilities?.npmAudit) {
        const audit = server.vulnerabilities.npmAudit;
        deductions += (audit.critical || 0) * 15;
        deductions += (audit.high || 0) * 10;
        deductions += (audit.moderate || 0) * 5;
        deductions += (audit.low || 0) * 2;
    }
    
    if (server.checks?.securityPractices) {
        additions += (server.checks.securityPractices.score || 0) * 2;
    }
    if (server.checks?.hasDependabot) additions += 3;
    if (server.checks?.hasCodeQL) additions += 3;
    if (server.checks?.hasSecurityPolicy) additions += 2;
    
    return `
        <div class="score-breakdown">
            <h4>Score Breakdown:</h4>
            <div class="score-details">
                <div class="score-item">
                    <span>Base Score</span>
                    <span>100</span>
                </div>
                ${deductions > 0 ? `
                    <div class="score-item negative">
                        <span>Vulnerability Deductions</span>
                        <span>-${deductions}</span>
                    </div>` : ''}
                ${additions > 0 ? `
                    <div class="score-item positive">
                        <span>Security Practice Bonus</span>
                        <span>+${additions}</span>
                    </div>` : ''}
                <div class="score-item" style="font-weight: bold; border-top: 1px solid #ddd; padding-top: 0.5rem; margin-top: 0.5rem;">
                    <span>Final Score</span>
                    <span>${server.securityScore}</span>
                </div>
            </div>
        </div>
    `;
}

function renderVulnerabilities(vulns) {
    if (!vulns || Object.keys(vulns).length === 0) return '';
    
    let html = `<div class="vulnerabilities">
        <i class="fas fa-info-circle info-icon" onclick="event.stopPropagation(); showInfoModal('vulnerabilities')" title="Click for vulnerability explanations"></i>`;
    
    if (vulns.critical > 0) {
        html += `<div class="vuln-item">
            <span class="vuln-badge critical">CRITICAL</span> ${vulns.critical}
        </div>`;
    }
    
    if (vulns.high > 0) {
        html += `<div class="vuln-item">
            <span class="vuln-badge high">HIGH</span> ${vulns.high}
        </div>`;
    }
    
    if (vulns.medium > 0) {
        html += `<div class="vuln-item">
            <span class="vuln-badge medium">MEDIUM</span> ${vulns.medium}
        </div>`;
    }
    
    if (vulns.low > 0) {
        html += `<div class="vuln-item">
            <span class="vuln-badge low">LOW</span> ${vulns.low}
        </div>`;
    }
    
    html += '</div>';
    return html;
}

function renderChecks(checks) {
    if (!checks) return '';
    
    const items = [];
    
    if (checks.hasSecurityPolicy) {
        items.push('<span class="check-item success"><i class="fas fa-check"></i> Security Policy</span>');
    }
    
    if (checks.hasDependabot) {
        items.push('<span class="check-item success"><i class="fas fa-check"></i> Dependabot</span>');
    }
    
    if (checks.hasCodeQL) {
        items.push('<span class="check-item success"><i class="fas fa-check"></i> CodeQL</span>');
    }
    
    if (checks.securityPractices) {
        const practices = checks.securityPractices;
        
        if (practices.hasTests) {
            items.push('<span class="check-item success"><i class="fas fa-check"></i> Tests</span>');
        }
        
        if (practices.hasCI) {
            items.push('<span class="check-item success"><i class="fas fa-check"></i> CI/CD</span>');
        }
        
        if (practices.hasLinter) {
            items.push('<span class="check-item success"><i class="fas fa-check"></i> Linter</span>');
        }
    }
    
    if (items.length === 0) return '';
    
    return `<div class="checks">
        <i class="fas fa-info-circle info-icon" onclick="event.stopPropagation(); showInfoModal('securityFeatures')" title="Click for security features explanations"></i>
        ${items.join('')}
    </div>`;
}

function renderErrors(errors) {
    if (!errors || errors.length === 0) return '';
    
    return errors.map(error => 
        `<div class="error-message"><i class="fas fa-exclamation-triangle"></i> ${error}</div>`
    ).join('');
}

function getScoreColor(score) {
    if (score >= 80) return '#34a853';
    if (score >= 60) return '#fbbc04';
    if (score >= 40) return '#ea8600';
    return '#d93025';
}

// Search functionality
document.getElementById('searchInput').addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    applyFilters();
});

// Filter functionality
document.getElementById('filterSelect').addEventListener('change', (e) => {
    applyFilters();
});

function applyFilters() {
    const searchQuery = document.getElementById('searchInput').value.toLowerCase();
    const filterValue = document.getElementById('filterSelect').value;
    
    filteredServers = servers.filter(server => {
        // Search filter
        const matchesSearch = !searchQuery || 
            server.name.toLowerCase().includes(searchQuery) ||
            server.owner.toLowerCase().includes(searchQuery) ||
            (server.description && server.description.toLowerCase().includes(searchQuery));
        
        // Category filter
        let matchesFilter = true;
        switch(filterValue) {
            case 'vulnerable':
                matchesFilter = (server.vulnerabilities?.osv?.total > 0) || 
                               (server.vulnerabilities?.npmAudit?.total > 0);
                break;
            case 'secure':
                matchesFilter = server.securityScore >= 80;
                break;
            case 'no-security':
                matchesFilter = !server.checks?.hasSecurityPolicy;
                break;
        }
        
        return matchesSearch && matchesFilter;
    });
    
    displayedServers = [...filteredServers];
    currentPage = 1; // Reset to first page when filtering
    sortServers();
}

// Sort functionality
document.getElementById('sortSelect').addEventListener('change', (e) => {
    sortServers();
});

function sortServers() {
    const sortBy = document.getElementById('sortSelect').value;
    
    displayedServers.sort((a, b) => {
        switch(sortBy) {
            case 'stars':
                return b.stars - a.stars;
            case 'score':
                return b.securityScore - a.securityScore;
            case 'critical':
                return (b.vulnerabilities?.osv?.critical || 0) - (a.vulnerabilities?.osv?.critical || 0);
            case 'high':
                return (b.vulnerabilities?.osv?.high || 0) - (a.vulnerabilities?.osv?.high || 0);
            default:
                return 0;
        }
    });
    
    renderServers();
}

// Share functions
function showShareModal() {
    shareModal.style.display = "block";
}

function getShareUrl() {
    return window.location.href;
}

function getShareTitle() {
    return "MCP Server Security Scanner - Check the security status of MCP servers";
}

function getShareDescription() {
    return `I found this awesome tool that scans MCP servers for security vulnerabilities. ${window.scanData.totalServers} servers analyzed!`;
}

function shareOnX() {
    const url = getShareUrl();
    const text = getShareTitle() + " - " + getShareDescription();
    window.open(`https://x.com/intent/tweet?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`, '_blank');
}

function shareOnFacebook() {
    const url = getShareUrl();
    window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}`, '_blank');
}

function shareOnLinkedIn() {
    const url = getShareUrl();
    const title = getShareTitle();
    const summary = getShareDescription();
    window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(url)}&title=${encodeURIComponent(title)}&summary=${encodeURIComponent(summary)}`, '_blank');
}

function shareOnWhatsApp() {
    const url = getShareUrl();
    const text = getShareTitle() + " - " + getShareDescription() + " " + url;
    window.open(`https://wa.me/?text=${encodeURIComponent(text)}`, '_blank');
}

function copyShareLink() {
    const url = getShareUrl();
    
    // Create a temporary input element
    const tempInput = document.createElement('input');
    tempInput.style.position = 'absolute';
    tempInput.style.left = '-1000px';
    tempInput.value = url;
    document.body.appendChild(tempInput);
    
    // Select and copy the URL
    tempInput.select();
    tempInput.setSelectionRange(0, 99999); // For mobile devices
    
    try {
        document.execCommand('copy');
        
        // Show notification
        const notification = document.getElementById('copyNotification');
        notification.classList.add('show');
        
        // Hide notification after animation
        setTimeout(() => {
            notification.classList.remove('show');
        }, 2000);
    } catch (err) {
        // Fallback for browsers that don't support execCommand
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(() => {
                const notification = document.getElementById('copyNotification');
                notification.classList.add('show');
                setTimeout(() => {
                    notification.classList.remove('show');
                }, 2000);
            });
        } else {
            alert('Copy link: ' + url);
        }
    }
    
    // Clean up
    document.body.removeChild(tempInput);
}

// Native Web Share API support (for mobile)
if (navigator.share) {
    // Add native share button for mobile devices in modal
    setTimeout(() => {
        const shareButtons = document.querySelector('.share-modal-buttons');
        if (shareButtons && !document.querySelector('.native-share')) {
            const nativeShareBtn = document.createElement('button');
            nativeShareBtn.className = 'share-modal-btn native-share';
            nativeShareBtn.style.background = '#4a5568';
            nativeShareBtn.innerHTML = '<i class="fas fa-share-square"></i> Native Share';
            nativeShareBtn.onclick = async () => {
                try {
                    await navigator.share({
                        title: getShareTitle(),
                        text: getShareDescription(),
                        url: getShareUrl()
                    });
                    shareModal.style.display = "none";
                } catch (err) {
                    if (err.name !== 'AbortError') {
                        console.error('Error sharing:', err);
                    }
                }
            };
            shareButtons.appendChild(nativeShareBtn);
        }
    }, 100);
}

// Initial render
renderServers();