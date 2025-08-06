# On the Lack of Robustness of Binary Function Similarity Systems
This repository contains the implementation of the attack framework proposed in the paper "On the Lack of Robustness of Binary Function Similarity Systems", accepted at **IEEE Euro S&P 2025**.

## Paper

The **arXiv** version of our paper is available [here](https://arxiv.org/abs/2412.04163).

If you use this code in your research, please cite our accademic paper:

```bibtex
@inproceedings{capozzi2025lack,
  title={On the Lack of Robustness of Binary Function Similarity Systems},
  author={Gianluca Capozzi and
                  Tong Tang and
                  Jie Wan and
                  Ziqi Yang and
                  Daniele Cono D'Elia and
                  Giuseppe Antonio Di Luna and
                  Lorenzo Cavallaro and
                  Leonardo Querzoni},
  booktitle={Proceedings of the 10th IEEE European Symposium on Security and Privacy (IEEE EuroS\&P '25)},
  pages={980-1001},
  year={2025},
  publisher={IEEE}
}
```

## Getting Started

### Build Docker image

Use the provided <code>Dockerfile</code> to build the Docker image. This will set up an environment with all the necessary dependencies:

```bash
docker build -t adv-sim .
```

### Running Experiments

To run the attacks, first start a container from the ```attack_framework``` folder:

```bash
docker run --gpus all \
    --name experiments \
    -dit -v "$(pwd):/app/vol/" \ 
    -w /app/vol/ \ 
    --entrypoint /bin/bash  adv-sim
```

Then, inside the container, you can launch experiments using the provided bash script:




## Acknowledgments
This work was partially supported by the Italian MUR National Recovery and Resilience Plan funded by the European Union - NextGenerationEU through projects SERICS (PE00000014) and Rome Technopole (ECS00000024).
