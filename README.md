Clone the Repository using https://github.com/arunthunderfrost27/cve_analysis.git


To run the Application

cd backend
python process.py =>To start the Flask App

sample input json file: https://services.nvd.nist.gov/rest/json/cves/2.0 

Concepts:

National Vulnerability Database=>
The NVD is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP).
This data enables automation of vulnerability management, security measurement, and compliance.

Common Vulnerabilities and Exposures=>
System that assigns unique identifiers to publicly known security vulnerabilities.Each CVE entry includes a description, impact, and references. 
It standardizes vulnerability tracking to help organizations address security risks effectively
This Application analyses the sample records of cve database

API Endpoints Descriptions:

POST /load_cve_data =>To load the cve data into mongodb.[database.py]

GET /api/cves/{cveId} =>To fetch the details of a specific CVE by its ID.

GET /api/cves =>To fetch list of cves at certain limit to manage pagination.

MongoDB Schema:

cve_metadata =>stores metadata related to each CVE, such as the CVE ID, source identifier,publication and modification dates and vulnerability status.

descriptions =>stores descriptions of the CVEs, including language and description text.

metrics =>stores the CVSS metrics for each CVE, including base score, vector string, access vector, complexity, and other impacts.

cpe =>stores Common Platform Enumeration (CPE) information for each CVE entry, including the vulnerable CPE matches and their criteria.










