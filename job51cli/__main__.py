"""CLI demo: fetch real 51job listings with the recovered sign, no login.

    python -m job51cli <keyword> [jobarea]

Prints resultbody.job.items from the public (noauth) job-search endpoint.
"""
import sys
from .client import Job51Client


def main():
    keyword = sys.argv[1] if len(sys.argv) > 1 else "python"
    jobarea = sys.argv[2] if len(sys.argv) > 2 else "000000"
    jobs = Job51Client().search_jobs(keyword, jobarea, size=15)
    print(f"关键词 '{keyword}' -> {len(jobs)} 个职位\n")
    for job in jobs:
        tags = " / ".join(job.get("jobTags", [])[:4])
        print(f"  [{job.get('jobId')}] {job.get('jobName')}  |  {job.get('jobAreaString')}  |  {tags}")


if __name__ == "__main__":
    main()
