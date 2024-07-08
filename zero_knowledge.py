from zksnark import Prover, Verifier

class ZeroKnowledgeProofs:
    @staticmethod
    def zk_prove(secret):
        prover = Prover(secret)
        proof = prover.generate_proof()
        return proof

    @staticmethod
    def zk_verify(proof):
        verifier = Verifier()
        return verifier.verify_proof(proof)
