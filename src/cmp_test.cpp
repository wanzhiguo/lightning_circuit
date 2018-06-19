#include <libsnark/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp> //--Agzs
//#include <libsnark/gadgetlib1/examples/simple_example.hpp>
//#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
//#include "libsnark/common/utils.hpp"
#include <boost/optional.hpp>
#include <boost/optional/optional_io.hpp>	// for output proof  --Zhiguo


using namespace libsnark;
using namespace std;

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
//template<typename ppzksnark_ppT>
//bool run_r1cs_gg_ppzksnark(const r1cs_example<Fr<ppzksnark_ppT> > &example)
//{
//    print_header("R1CS GG-ppzkSNARK Generator");
//    r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(example.constraint_system);
//    printf("\n"); print_indent(); print_mem("after generator");
//
//    print_header("Preprocess verification key");
//    r1cs_gg_ppzksnark_processed_verification_key<ppzksnark_ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppzksnark_ppT>(keypair.vk);
//
//    print_header("R1CS GG-ppzkSNARK Prover");
//    r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof = r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
//    printf("\n"); print_indent(); print_mem("after prover");
//
//    print_header("R1CS GG-ppzkSNARK Verifier");
//    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(keypair.vk, example.primary_input, proof);
//    printf("\n"); print_indent(); print_mem("after verifier");
//    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
//
//    print_header("R1CS GG-ppzkSNARK Online Verifier");
//    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppzksnark_ppT>(pvk, example.primary_input, proof);
//    assert(ans == ans2);
//
//    return ans;
//}

//template<typename ppzksnark_ppT>
//void test_r1cs_gg_ppzksnark(size_t num_constraints, size_t input_size)
//{
//    r1cs_example<Fr<ppzksnark_ppT> > example = generate_r1cs_example_with_binary_input<Fr<ppzksnark_ppT> >(num_constraints, input_size);
//    const bool bit = run_r1cs_gg_ppzksnark<ppzksnark_ppT>(example);
//    assert(bit);
//}

// int main () {
//     default_r1cs_gg_ppzksnark_pp::init_public_params();
//     test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

//     return 0;
// }
#define DEBUG 1


template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
protoboard<Fr<ppzksnark_ppT>> pb)
{
//    typedef Fr<ppzksnark_ppT> FieldT;

//    protoboard<FieldT> pb;
//    l_gadget<FieldT> g(pb);
//    g.generate_r1cs_constraints();
//    g.generate_r1cs_witness(h1, h2, x, r1, r2);

    if (!pb.is_satisfied()) {
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key, r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input;

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}



// test_comparison_gadget_with_instance
template<typename ppzksnark_ppT> //--Agzs
void test_comparison_gadget_with_instance(const size_t n, const size_t a, const size_t b)
{
    printf("testing comparison_gadget on all %zu bit inputs: a = %zu, b = %zu\n", n, a, b);

    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    pb_variable<FieldT> A, B, less, less_or_eq;
    A.allocate(pb, "A");
    B.allocate(pb, "B");
    less.allocate(pb, "less");
    less_or_eq.allocate(pb, "less_or_eq");

    comparison_gadget<FieldT> comparison(pb, n, A, B, less, less_or_eq, "cmp");
    comparison.generate_r1cs_constraints();
    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair =  r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    if (a < 1ul<<n && b < 1ul<<n)
    {
        pb.val(A) = FieldT(a);
        pb.val(B) = FieldT(b);

        comparison.generate_r1cs_witness();
        
#ifdef DEBUG
        printf("positive test for %zu < %zu\n", a, b);
#endif
        assert(pb.val(less) == (a < b ? FieldT::one() : FieldT::zero()));
        assert(pb.val(less_or_eq) == (a <= b ? FieldT::one() : FieldT::zero()));
        assert(pb.is_satisfied());

        if (pb.val(less_or_eq) == FieldT::one())
        {
            if (pb.val(less) == FieldT::one()) {
                printf("result test for %zu < %zu\n", a, b);
            } else {
                printf("result test for %zu = %zu\n", a, b);
            }
        } else {
            printf("result test for %zu > %zu\n", a, b);
        }
	// generate proof
        boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> proof = generate_proof(keypair.pk, pb);
        cout<<"the final proof:"<<*proof<<endl;
        // verify proof
	verify_proof(keypair.vk, *proof);
	//r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(keypair.vk, input, *proof);


    } else {
        printf("the size of a = %zu or b = %zu is larger than the %zu bit inputs\n", a, b, n);
    }

    print_time("comparison tests successful");
    printf("\n");
}


template<typename ppzksnark_ppT>
void my_test_comparison_gadget(const size_t n)
{
    printf("testing comparison_gadget on all %zu bit inputs\n", n);
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    pb_variable<FieldT> A, B, less, less_or_eq;
    A.allocate(pb, "A");
    B.allocate(pb, "B");
    less.allocate(pb, "less");
    less_or_eq.allocate(pb, "less_or_eq");

    comparison_gadget<FieldT> cmp(pb, n, A, B, less, less_or_eq, "cmp");
    cmp.generate_r1cs_constraints();

    // Check constraints of the R1CS system
//    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
//    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
//
//    r1cs_ppzksnark_generator<ppzksnark_ppT> keypair =  r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    for (size_t a = 0; a < 1ul<<n; ++a)
    {
        for (size_t b = 0; b < 1ul<<n; ++b)
        {
            pb.val(A) = FieldT(a);
            pb.val(B) = FieldT(b);

            cmp.generate_r1cs_witness();

#ifdef DEBUG
            printf("positive test for %zu < %zu\n", a, b);
#endif
            assert(pb.val(less) == (a < b ? FieldT::one() : FieldT::zero()));
            assert(pb.val(less_or_eq) == (a <= b ? FieldT::one() : FieldT::zero()));
            assert(pb.is_satisfied());
        }
    }

    print_time("comparison tests successful");
}


int main () {
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    //test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

    print_header("#             test comparison gadget");

    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(6, 45, 40);
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(6, 40, 40);
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(6, 40, 45);
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(2, 0, 0);
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(2, 0, 1);
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(2, 1, 0);
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(2, 45, 40);
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(255, 45, 40);
    //test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(255, 40, 45); //有问题
//    test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(8, 40, 245);
//    my_test_comparison_gadget<default_r1cs_gg_ppzksnark_pp>(4);
    return 0;
}

