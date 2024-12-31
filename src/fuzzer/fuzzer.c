
/*

// !!!!! NOTE !!!!!
// This file is a fuzzer which is based on the code found in ffmpeg in libavfilter/af_sofalizer.c https://github.com/FFmpeg/FFmpeg/blob/master/libavfilter/af_sofalizer.c

static int preload_sofa(AVFilterContext *ctx, char *filename, int *samplingrate)
{
    struct SOFAlizerContext *s = ctx->priv;
    struct MYSOFA_HRTF *mysofa;
    char *license;
    int ret;

    mysofa = mysofa_load(filename, &ret);
    s->sofa.hrtf = mysofa;
    if (ret || !mysofa) {
        av_log(ctx, AV_LOG_ERROR, "Can't find SOFA-file '%s'\n", filename);
        return AVERROR(EINVAL);
    }

    ret = mysofa_check(mysofa);
    if (ret != MYSOFA_OK) {
        av_log(ctx, AV_LOG_ERROR, "Selected SOFA file is invalid. Please select valid SOFA file.\n");
        return ret;
    }

    if (s->normalize)
        mysofa_loudness(s->sofa.hrtf);

    if (s->minphase)
        mysofa_minphase(s->sofa.hrtf, 0.01f);

    mysofa_tocartesian(s->sofa.hrtf);

    s->sofa.lookup = mysofa_lookup_init(s->sofa.hrtf);
    if (s->sofa.lookup == NULL)
        return AVERROR(EINVAL);

    if (s->interpolate)
        s->sofa.neighborhood = mysofa_neighborhood_init_withstepdefine(s->sofa.hrtf,
                                                                       s->sofa.lookup,
                                                                       s->anglestep,
                                                                       s->radstep);

    s->sofa.fir = av_calloc(s->sofa.hrtf->N * s->sofa.hrtf->R, sizeof(*s->sofa.fir));
    if (!s->sofa.fir)
        return AVERROR(ENOMEM);

    if (mysofa->DataSamplingRate.elements != 1)
        return AVERROR(EINVAL);
    av_log(ctx, AV_LOG_DEBUG, "Original IR length: %d.\n", mysofa->N);
    *samplingrate = mysofa->DataSamplingRate.values[0];
    license = mysofa_getAttribute(mysofa->attributes, (char *)"License");
    if (license)
        av_log(ctx, AV_LOG_INFO, "SOFA license: %s\n", license);

    return 0;
}


MYSOFA_EXPORT struct MYSOFA_NEIGHBORHOOD *mysofa_neighborhood_init_withstepdefine(
    struct MYSOFA_HRTF *hrtf, struct MYSOFA_LOOKUP *lookup,
    float neighbor_angle_step, float neighbor_radius_step);

*/


// Main fuzzer functions...

// MYSOFA_EXPORT struct MYSOFA_HRTF *mysofa_load_data(const char *data, size_t size, int *err);


#include "../hrtf/mysofa.h"
#include "../hrtf/tools.h"
// #include "json.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	// Main fuzzer

	struct MYSOFA_HRTF *mysofa;
	struct MYSOFA_LOOKUP *lookup;
	char *license;
	int ret;




	mysofa = mysofa_load_data(Data, Size, &ret);
	//s->sofa.hrtf = mysofa;
	if (ret || !mysofa) {
		return 0;
		//av_log(ctx, AV_LOG_ERROR, "Can't find SOFA-file '%s'\n", filename);
		//return AVERROR(EINVAL);
	}

	ret = mysofa_check(mysofa);
	if (ret != MYSOFA_OK) {
		//av_log(ctx, AV_LOG_ERROR, "Selected SOFA file is invalid. Please select valid SOFA file.\n");
		return 0; // ret;
	}

	//if (s->normalize)
	mysofa_loudness(mysofa);

	//if (s->minphase)
	mysofa_minphase(mysofa, 0.01f);

	mysofa_tocartesian(mysofa);

	lookup = mysofa_lookup_init(mysofa);
	if (lookup == NULL)
	    return 0;

	//if (s->interpolate)
	// s->sofa.neighborhood = mysofa_neighborhood_init_withstepdefine(s->sofa.hrtf, s->sofa.lookup, s->anglestep, s->radstep);

	mysofa_neighborhood_init_withstepdefine(mysofa, lookup, 0.1f, 0.1f); // Maybe do something like this???
	// float neighbor_angle_step, float neighbor_radius_step

	license = mysofa_getAttribute(mysofa->attributes, (char *)"License");


	return 0;  // Values other than 0 and -1 are reserved for future use.
}

