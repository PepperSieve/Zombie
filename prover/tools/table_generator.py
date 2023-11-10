text = """INFO:root:transcript generation time 0.1743488311767578
INFO:root:assignment generation time 4.776968479156494
Evaluation Time  0.722
write Buffer Time 3.459
INFO:root:assignment preprocess time 2.6381402015686035
INFO:root:proof generation time 2.3225109577178955
INFO:root:total time 9.911968469619751
INFO:root:verify time 0.004124879837036133"""

times = [float(line.split(' ')[-1]) for line in text.split('\n')]
transcript_time = times[0]
assignment_time = times[1]
evaluation_time = times[2]
buffer_time = times[3]
preprocess_time = times[4]
prove_time = times[5]
total_time = times[6]
verify_time = times[7]
intrinsic_time = transcript_time + evaluation_time + prove_time
overhead_time = total_time - intrinsic_time
network_time = assignment_time - buffer_time - evaluation_time

table = f"""
| Name                       | Time  |
| ----                       | ----  |
| `prover`                   |       |
| transcript generation time | {transcript_time:.3f} |
| assignment generation time | {assignment_time:.3f} |
| - circuit evaluation time  | {evaluation_time:.3f} |
| - write to buffer time     | {buffer_time:.3f} |
| - network cost             | {network_time:.3f} |
| assignment preprocess time | {preprocess_time:.3f} |
| proof generation time      | {prove_time:.3f} |
| prover total time          | {total_time:.3f} |
| `prover overhead`          |       |
| prover intrinsic time      | {intrinsic_time:.3f} |
| prover overhead            | {overhead_time:.3f} |
| `verifier`                 |       |
|verifier total time         | {verify_time:.5f} |
"""

print(table)


