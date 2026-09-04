"""CLI demo: fetch real 51job data with the recovered sign, no login.

    python -m job51cli <keyword> [jobarea]     # search: list real jobs
    python -m job51cli detail <jobId>          # full job detail

Both hit public (noauth) endpoints; the sign is the only gate.
"""
import sys
from .client import Job51Client


def main():
    args = sys.argv[1:]
    cli = Job51Client()
    if args and args[0] == "detail" and len(args) > 1:
        info = cli.job_detail(args[1]).get("detailJobInfo", {})
        print(f"{info.get('jobName')}  |  {info.get('companyName')}")
        print(f"  薪资: {info.get('provideSalaryString')}   经验: {info.get('workYearString')}   "
              f"学历: {info.get('degreeString')}")
        area = info.get("jobAreaLevelDetail", {})
        print(f"  地区: {area.get('cityString')}·{area.get('districtString')}   "
              f"公司: {info.get('companyTypeString')} / {info.get('companySizeString')} / {info.get('industryType1String')}")
        print(f"  福利: {info.get('welfare')}")
        print(f"\n{info.get('jobDescribe', '')}")
        return
    keyword = args[0] if args else "python"
    jobarea = args[1] if len(args) > 1 else "000000"
    jobs = cli.search_jobs(keyword, jobarea, size=15)
    print(f"关键词 '{keyword}' -> {len(jobs)} 个职位（详情: python -m job51cli detail <jobId>）\n")
    for job in jobs:
        comp = job.get("companyName") or job.get("fullCompanyName") or ""
        sal = job.get("provideSalaryString") or "面议"
        size_ = job.get("companySizeString") or ""
        print(f"  [{job.get('jobId')}] {job.get('jobName')}  |  {sal}  |  {job.get('jobAreaString')}")
        print(f"      {comp}  ({job.get('companyTypeString','')} {size_})  |  "
              f"{job.get('workYearString','')} {job.get('degreeString','')}")


if __name__ == "__main__":
    main()
