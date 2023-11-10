from . import poseidon_constants_bn
from . import poseidon_constants_dalek
import time

class PoseidonHashGenerator:

    def __init__(self, curve_choice):
        if curve_choice == 'bn128':
            self.p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            self.POSEIDON_C = poseidon_constants_bn.POSEIDON_C
            self.POSEIDON_M = poseidon_constants_bn.POSEIDON_M
        elif curve_choice == 'dalek':
            self.p = 2 ** 252 + 27742317777372353535851937790883648493 
            self.POSEIDON_C = poseidon_constants_dalek.POSEIDON_C
            self.POSEIDON_M = poseidon_constants_dalek.POSEIDON_M
        else:
            raise NotImplementedError


    def exp5(self, in1):
        in2 = in1*in1 % self.p
        in4 = in2*in2 % self.p
        in5 = in4*in1 % self.p

        return in5


    def ark(self, state, C, r):
        for i in range(0, len(state)):
            state[i] = state[i] + C[i+r] % self.p

        return state


    def mix(self, state, M):
        lc = 0
        output = []

        for i in range(0, len(state)):
            lc = 0
            for j in range(0, len(state)):
                lc = lc + M[i][j]*state[j] % self.p
            output.append(lc)

        return output


    def sbox(self, nRoundsF, nRoundsP, state, i):
        if ((i < nRoundsF/2) or (i >= nRoundsF/2 + nRoundsP)):
            for j in range(0, len(state)):
                state[j] = self.exp5(state[j])
        else:
            state[0] = self.exp5(state[0])

        return state


    def poseidon_hash(self, input):

        nInputs = len(input)
        N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63]
        t = nInputs + 1
        nRoundsF = 8
        nRoundsP = N_ROUNDS_P[t - 2]

        C = self.POSEIDON_C(t)
        M = self.POSEIDON_M(t)

        state = [0]
        for item in input:
            state.append(item)

        for i in range(0, nRoundsF + nRoundsP):
            # print(i," ", state[0])
            # print(i," in ",hex(state[0]),state[0])
            state = self.ark(state, C, i*t)
            # print(i," ark ",hex(state[0]), state[0])
            state = self.sbox(nRoundsF, nRoundsP, state, i)
            # print(i," sbox ",state[0])
            state = self.mix(state, M)
            # print(i," mix ",state[0])

        output = state[0] % self.p
        return output

# a = poseidon_hash([3993726729728456562288376524736781253942224580193245007545935011759967092819, 20532736310324258262994538691311925383259813537971010774634242964482628474019])
# print(a)
# 0x295f05722342fa8f3598a3fef7b69add734ea2ab1f64c9a6974d955b113a696f
