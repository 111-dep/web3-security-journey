# Web3 Security Researcher 
## 👨‍💻 About Me

Just a regular guy trying to make it in Web3 security.  
Biology major in university, later worked on Java backend and bioinformatics. After a couple of career shifts, started self-studying smart contract auditing in October 2025.  
Still very much learning — this repo is where I keep my findings from contests. Feedback welcome.
---
### Competitive Auditing Experience  

**Sherlock Audit Contest**  
*stNXM*  
- Identified and confirmed 2 issues (1 High, 1 Medium)  
  - High: Owner can zero out reported AUM by removing staking IDs, then mint massive shares at near-zero price and drain vault 
  - Medium: Oracle startup window enforces overly strict price cap causing denial-of-service during slight early appreciation  

**Sherlock Audit Contest**  
*Monolith* – December 2025  
- Identified and confirmed 1 High-severity issue  
  - High: Chainlink oracle stale price drops to 1 wei without disabling redemption, allowing malicious draining of protocol funds  

**Code4rena Audit Contest**  
*SukukFi*  
- Identified and confirmed 2 issues (1 High, 1 Medium)  
  - High: Critical: Arbitrary theft of user funds in `WERC7575Vault` due to missing allowance check on `redeem/withdraw`  
  - Medium: DoS via Dust Transfer Prevents Vault Unregistration  

**Code4rena Audit Contest**  
*Swafe* – November 2025  
- Identified and confirmed 2 Medium-severity issues  
  - Medium: Lack of replay protection for guardian shares allows malicious overwrite and DoS
  - Medium: Malicious thrashing of `rec.pke` can permanently block account recovery  

**Code4rena Audit Contest**  
*Reflector V3*  
- Identified and confirmed 1 High-severity issue  
  - High: [Critical Authorization Bypass: Anyone Can Manipulate Oracle Invocation Costs, Disrupting the Entire Economic Model of ReflectorBeam](https://code4rena.com/audits/2025-11-sukukfi/submissions?uid=36G42wMVPdT)

---

## 📫 Contact

Open to **Security Audit** roles (Remote) or private audit engagements.

*   **Email:** [tangjs98@qq.com]
*   **Twitter/X:** [https://x.com/TangSong29002]
*   **Github:** [(https://github.com/111-dep/web3-security-journey)]