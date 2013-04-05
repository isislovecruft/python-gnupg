This patches folder is managed by quilt, which is a tool for automatic patch
application and removal. To use quilt with the patches in this directory,
navigate to the top level directory of this repository, and do:

 $ quilt setup patches/series

To add an externally created patch (in other words, one created with ```diff
--git``` or ```git diff```), place that .patch or .diff file in this directory,
and do:

 $ quilt import patches/<patchfile>

Then, to apply the new patch, do:

 $ quilt push

Removing patches from the stack can be done with:

 $ quilt pop

Please see the man quilt(1) for more information on adding and importing new
patches. The debian package maintainer guides also have chapters on quilt
usage.
